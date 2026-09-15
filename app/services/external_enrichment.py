from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urljoin

import psycopg
import requests
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.db.connection import get_connection

DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."
HTTP_TIMEOUT_SECONDS = 6
EXTERNAL_CACHE_TTL = timedelta(days=7)
USER_AGENT = "RouteBrain/1.0 (example-server external enrichment)"

IANA_RDAP_BOOTSTRAPS = {
    "asn": "https://data.iana.org/rdap/asn.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}

COUNTRY_NAME_MAP = {
    "UNITED STATES": "US",
    "UNITED STATES OF AMERICA": "US",
    "U.S.": "US",
    "P.R. CHINA": "CN",
    "P.R.CHINA": "CN",
    "PR CHINA": "CN",
    "CHINA": "CN",
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
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(value)
    return value


def _json_value(value: Any) -> Json:
    return Json(_safe_json(value))


def _normalize_text(value: str | None) -> str:
    return " ".join(str(value or "").split()).strip()


def _normalize_asn(value: int | str) -> int:
    asn = int(str(value).strip())
    if asn <= 0:
        raise ValueError("ASN inválido.")
    return asn


def _normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(str(value).strip()))


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


def _safe_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    safe = dict(row)
    if isinstance(safe.get("data"), (dict, list)):
        safe["data"] = _safe_json(safe["data"])
    if isinstance(safe.get("raw_data"), (dict, list)):
        safe["raw_data"] = _safe_json(safe["raw_data"])
    return safe


def _cache_key(source: str, entity_type: str, entity_value: str) -> str:
    return f"{_normalize_text(source).lower()}:{_normalize_text(entity_type).lower()}:{_normalize_text(entity_value).lower()}"


def _cache_freshness(created_at: datetime | None, expires_at: datetime | None) -> dict[str, Any]:
    created = created_at if isinstance(created_at, datetime) else None
    expiry = expires_at if isinstance(expires_at, datetime) else None
    now = _now()

    if created is None:
        return {
            "status": "missing",
            "age_seconds": None,
            "age_human": None,
            "expires_at": expiry.isoformat() if expiry else None,
            "recommended_action": "atualizar",
        }

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if expiry is not None and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    age_seconds = max(0, int((now - created).total_seconds()))
    ttl_seconds = int(EXTERNAL_CACHE_TTL.total_seconds())
    if expiry is None:
        expiry = created + EXTERNAL_CACHE_TTL
    stale_window = expiry + EXTERNAL_CACHE_TTL
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
        "status": status,
        "age_seconds": age_seconds,
        "age_human": f"{age_seconds // 86400}d {(age_seconds % 86400) // 3600}h {(age_seconds % 3600) // 60}m" if age_seconds >= 3600 else f"{age_seconds // 60}m {age_seconds % 60}s",
        "ttl_seconds": ttl_seconds,
        "expires_at": expiry.isoformat() if expiry else None,
        "recommended_action": recommended_action,
    }


def _record_run(
    conn: psycopg.Connection,
    *,
    source: str,
    entity_type: str,
    entity_value: str,
    status: str,
    cache_hit: bool = False,
    error: str | None = None,
    report_path: str | None = None,
) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into external_enrichment_runs (
              source,
              entity_type,
              entity_value,
              status,
              cache_hit,
              started_at,
              finished_at,
              error,
              report_path
            )
            values (%s, %s, %s, %s, %s, now(), now(), %s, %s)
            returning id;
            """,
            (source, entity_type, entity_value, status, cache_hit, error, report_path),
        )
        row = cur.fetchone()
        return int(row[0]) if row is not None else 0


def _finish_run(
    conn: psycopg.Connection,
    run_id: int,
    *,
    status: str,
    cache_hit: bool = False,
    error: str | None = None,
    report_path: str | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            update external_enrichment_runs
            set status = %s,
                cache_hit = %s,
                finished_at = now(),
                error = %s,
                report_path = coalesce(%s, report_path)
            where id = %s;
            """,
            (status, cache_hit, error, report_path, run_id),
        )


def _upsert_cache(
    conn: psycopg.Connection,
    *,
    cache_key: str,
    source: str,
    entity_type: str,
    entity_value: str,
    status: str,
    data: dict[str, Any],
    error: str | None = None,
    expires_at: datetime | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into external_enrichment_cache (
              cache_key,
              source,
              entity_type,
              entity_value,
              status,
              data,
              error,
              fetched_at,
              expires_at
            )
            values (%s, %s, %s, %s, %s, %s, %s, now(), %s)
            on conflict (cache_key)
            do update set
              source = excluded.source,
              entity_type = excluded.entity_type,
              entity_value = excluded.entity_value,
              status = excluded.status,
              data = excluded.data,
              error = excluded.error,
              fetched_at = excluded.fetched_at,
              expires_at = excluded.expires_at,
              updated_at = now();
            """,
            (
                cache_key,
                source,
                entity_type,
                entity_value,
                status,
                _json_value(data),
                error,
                expires_at,
            ),
        )


def _upsert_external_asn(
    conn: psycopg.Connection,
    *,
    asn: int,
    source_priority: str | None,
    organization_name: str | None,
    country: str | None,
    network_name: str | None,
    website: str | None,
    looking_glass: str | None,
    route_server: str | None,
    network_type: str | None,
    info_type: str | None,
    info_prefixes4: int | None,
    info_prefixes6: int | None,
    peering_policy: str | None,
    source: str,
    confidence: str,
    raw_data: dict[str, Any],
    fetched_at: datetime,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into external_asn_enrichment (
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
            )
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (asn)
            do update set
              source_priority = excluded.source_priority,
              organization_name = excluded.organization_name,
              country = excluded.country,
              network_name = excluded.network_name,
              website = excluded.website,
              looking_glass = excluded.looking_glass,
              route_server = excluded.route_server,
              network_type = excluded.network_type,
              info_type = excluded.info_type,
              info_prefixes4 = excluded.info_prefixes4,
              info_prefixes6 = excluded.info_prefixes6,
              peering_policy = excluded.peering_policy,
              source = excluded.source,
              confidence = excluded.confidence,
              raw_data = excluded.raw_data,
              fetched_at = excluded.fetched_at,
              updated_at = now();
            """,
            (
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
                _json_value(raw_data),
                fetched_at,
            ),
        )


def _upsert_external_ip(
    conn: psycopg.Connection,
    *,
    ip: str,
    asn: int | None,
    organization_name: str | None,
    country: str | None,
    network_name: str | None,
    source: str,
    confidence: str,
    raw_data: dict[str, Any],
    fetched_at: datetime,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            insert into external_ip_enrichment (
              ip,
              asn,
              organization_name,
              country,
              network_name,
              source,
              confidence,
              raw_data,
              fetched_at
            )
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            on conflict (ip)
            do update set
              asn = excluded.asn,
              organization_name = excluded.organization_name,
              country = excluded.country,
              network_name = excluded.network_name,
              source = excluded.source,
              confidence = excluded.confidence,
              raw_data = excluded.raw_data,
              fetched_at = excluded.fetched_at,
              updated_at = now();
            """,
            (ip, asn, organization_name, country, network_name, source, confidence, _json_value(raw_data), fetched_at),
        )


def _get_cached_row(
    source: str,
    entity_type: str,
    entity_value: str,
    *,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any] | None:
    row = _fetch_one(
        """
        select
          id,
          cache_key,
          source,
          entity_type,
          entity_value,
          status,
          data,
          error,
          fetched_at,
          expires_at,
          created_at,
          updated_at
        from external_enrichment_cache
        where cache_key = %s
        limit 1;
        """,
        (_cache_key(source, entity_type, entity_value),),
        conn=conn,
    )
    if row is None:
        return None
    row = _safe_row(row)
    row["cache_hit"] = True
    row["freshness"] = _cache_freshness(row.get("created_at"), row.get("expires_at"))
    return row


def get_cached_enrichment(
    source: str,
    entity_type: str,
    entity_value: str,
    *,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any] | None:
    return _get_cached_row(source, entity_type, entity_value, conn=conn)


def save_enrichment_cache(
    *,
    source: str,
    entity_type: str,
    entity_value: str,
    status: str,
    data: dict[str, Any],
    error: str | None = None,
    expires_at: datetime | None = None,
    conn: psycopg.Connection | None = None,
    normalized_asn: dict[str, Any] | None = None,
    normalized_ip: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_entity_value = _normalize_text(entity_value)
    key = _cache_key(source, entity_type, normalized_entity_value)

    if conn is not None:
        _upsert_cache(
            conn,
            cache_key=key,
            source=source,
            entity_type=entity_type,
            entity_value=normalized_entity_value,
            status=status,
            data=data,
            error=error,
            expires_at=expires_at,
        )
        if normalized_asn is not None:
            _upsert_external_asn(conn, **normalized_asn)
        if normalized_ip is not None:
            _upsert_external_ip(conn, **normalized_ip)
        return get_cached_enrichment(source, entity_type, normalized_entity_value, conn=conn) or {}

    with get_connection() as fresh_conn:
        _upsert_cache(
            fresh_conn,
            cache_key=key,
            source=source,
            entity_type=entity_type,
            entity_value=normalized_entity_value,
            status=status,
            data=data,
            error=error,
            expires_at=expires_at,
        )
        if normalized_asn is not None:
            _upsert_external_asn(fresh_conn, **normalized_asn)
        if normalized_ip is not None:
            _upsert_external_ip(fresh_conn, **normalized_ip)
        return get_cached_enrichment(source, entity_type, normalized_entity_value, conn=fresh_conn) or {}


@lru_cache(maxsize=3)
def _bootstrap_payload(kind: str) -> dict[str, Any]:
    if kind not in IANA_RDAP_BOOTSTRAPS:
        raise ValueError("Bootstrap RDAP inválido.")
    response = requests.get(
        IANA_RDAP_BOOTSTRAPS[kind],
        timeout=HTTP_TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Bootstrap RDAP inesperado.")
    return payload


def _bootstrap_services(kind: str) -> list[list[Any]]:
    payload = _bootstrap_payload(kind)
    services = payload.get("services") or []
    if not isinstance(services, list):
        return []
    return [service for service in services if isinstance(service, list) and len(service) >= 2]


def _service_for_asn(asn: int) -> str:
    for service in _bootstrap_services("asn"):
        ranges = service[0] or []
        urls = service[1] or []
        if not isinstance(ranges, list) or not isinstance(urls, list):
            continue
        for range_item in ranges:
            text = str(range_item).strip()
            if not text:
                continue
            if "-" in text:
                try:
                    start, end = [int(part.strip()) for part in text.split("-", 1)]
                except ValueError:
                    continue
                if start <= asn <= end:
                    return str(urls[0])
            else:
                try:
                    if int(text) == asn:
                        return str(urls[0])
                except ValueError:
                    continue
    raise RuntimeError(f"Não foi possível localizar bootstrap RDAP para ASN {asn}.")


def _service_for_ip(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    best_url: str | None = None
    best_prefixlen = -1
    kind = "ipv6" if address.version == 6 else "ipv4"
    for service in _bootstrap_services(kind):
        prefixes = service[0] or []
        urls = service[1] or []
        if not isinstance(prefixes, list) or not isinstance(urls, list):
            continue
        for prefix_item in prefixes:
            text = str(prefix_item).strip()
            if not text:
                continue
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError:
                continue
            if address in network and network.prefixlen > best_prefixlen:
                best_prefixlen = network.prefixlen
                best_url = str(urls[0])
    if best_url is None:
        raise RuntimeError(f"Não foi possível localizar bootstrap RDAP para IP {ip}.")
    return best_url


def _http_get_json(url: str) -> dict[str, Any]:
    response = requests.get(
        url,
        timeout=HTTP_TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Resposta JSON inesperada.")
    return payload


def _extract_vcard(entity: dict[str, Any]) -> dict[str, Any]:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return {}
    result: dict[str, Any] = {}
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        name = str(item[0] or "").lower()
        value = item[3]
        result[name] = value
    return result


def _extract_country_from_entity(entity: dict[str, Any]) -> str | None:
    if not isinstance(entity, dict):
        return None
    country = entity.get("country")
    if isinstance(country, str) and country.strip():
        return country.strip().upper()
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
        for item in vcard[1]:
            if not isinstance(item, list) or not item:
                continue
            if str(item[0] or "").lower() != "adr":
                continue
            if len(item) >= 2 and isinstance(item[1], dict):
                    label = item[1].get("label")
                    if isinstance(label, str) and label.strip():
                        lines = [line.strip() for line in label.splitlines() if line.strip()]
                        if lines:
                            return COUNTRY_NAME_MAP.get(lines[-1].upper(), lines[-1].upper())
            if len(item) >= 4 and isinstance(item[3], list) and item[3]:
                candidate = item[3][-1]
                if isinstance(candidate, str) and candidate.strip():
                    return COUNTRY_NAME_MAP.get(candidate.strip().upper(), candidate.strip().upper())
    vcard_data = _extract_vcard(entity)
    adr = vcard_data.get("adr")
    if isinstance(adr, dict):
        label = adr.get("label")
        if isinstance(label, str) and label.strip():
            lines = [line.strip() for line in label.splitlines() if line.strip()]
            if lines:
                return COUNTRY_NAME_MAP.get(lines[-1].upper(), lines[-1].upper())
    if isinstance(adr, list) and len(adr) >= 7:
        country_value = adr[-1]
        if isinstance(country_value, str) and country_value.strip():
            return COUNTRY_NAME_MAP.get(country_value.strip().upper(), country_value.strip().upper())
    return None


def _extract_entity_name(entity: dict[str, Any]) -> str | None:
    if not isinstance(entity, dict):
        return None
    vcard = _extract_vcard(entity)
    fn = vcard.get("fn")
    if isinstance(fn, str) and fn.strip():
        return fn.strip()
    name = entity.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    handle = entity.get("handle")
    if isinstance(handle, str) and handle.strip():
        return handle.strip()
    return None


def _extract_any_origin_asns(payload: dict[str, Any]) -> list[int]:
    origin_asns: list[int] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_lower = str(key).lower()
                if "originautnum" in key_lower:
                    if isinstance(item, list):
                        for candidate in item:
                            try:
                                origin_asns.append(_normalize_asn(candidate))
                            except Exception:
                                continue
                    else:
                        try:
                            origin_asns.append(_normalize_asn(item))
                        except Exception:
                            pass
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(payload)
    return sorted({asn for asn in origin_asns if asn > 0})


def fetch_rdap_ip(ip: str) -> dict[str, Any]:
    normalized_ip = _normalize_ip(ip)
    service = _service_for_ip(normalized_ip)
    payload = _http_get_json(urljoin(service if service.endswith("/") else service + "/", f"ip/{normalized_ip}"))
    entities = payload.get("entities") or []
    country = payload.get("country")
    if not isinstance(country, str) or not country.strip():
        for entity in entities:
            if isinstance(entity, dict):
                country = _extract_country_from_entity(entity)
                if country:
                    break
    organization_name = None
    for entity in entities:
        if isinstance(entity, dict):
            organization_name = _extract_entity_name(entity)
            if organization_name:
                break
    origin_asns = _extract_any_origin_asns(payload)
    network_name = payload.get("name")
    if not isinstance(network_name, str) or not network_name.strip():
        network_name = payload.get("handle")
    result = {
        "source": "rdap",
        "entity_type": "ip",
        "entity_value": normalized_ip,
        "status": "ok",
        "ip": normalized_ip,
        "asn": origin_asns[0] if origin_asns else None,
        "organization_name": organization_name,
        "country": country.strip().upper() if isinstance(country, str) and country.strip() else None,
        "network_name": network_name if isinstance(network_name, str) else None,
        "handle": payload.get("handle"),
        "raw_data": payload,
        "fetched_at": _now(),
        "expires_at": _now() + EXTERNAL_CACHE_TTL,
    }
    return result


def fetch_rdap_asn(asn: int | str) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    service = _service_for_asn(normalized_asn)
    payload = _http_get_json(urljoin(service if service.endswith("/") else service + "/", f"autnum/{normalized_asn}"))
    entities = payload.get("entities") or []
    country = payload.get("country")
    if not isinstance(country, str) or not country.strip():
        for entity in entities:
            if isinstance(entity, dict):
                country = _extract_country_from_entity(entity)
                if country:
                    break
    organization_name = None
    for entity in entities:
        if isinstance(entity, dict):
            organization_name = _extract_entity_name(entity)
            if organization_name:
                break
    network_name = payload.get("name")
    if not isinstance(network_name, str) or not network_name.strip():
        network_name = payload.get("handle")
    result = {
        "source": "rdap",
        "entity_type": "asn",
        "entity_value": str(normalized_asn),
        "status": "ok",
        "asn": normalized_asn,
        "organization_name": organization_name,
        "country": country.strip().upper() if isinstance(country, str) and country.strip() else None,
        "network_name": network_name if isinstance(network_name, str) else None,
        "handle": payload.get("handle"),
        "startAutnum": payload.get("startAutnum"),
        "endAutnum": payload.get("endAutnum"),
        "raw_data": payload,
        "fetched_at": _now(),
        "expires_at": _now() + EXTERNAL_CACHE_TTL,
    }
    return result


def fetch_peeringdb_network_by_asn(asn: int | str) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    response = requests.get(
        f"https://www.peeringdb.com/api/net?asn={normalized_asn}",
        timeout=HTTP_TIMEOUT_SECONDS,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    if response.status_code == 429:
        raise RuntimeError("PeeringDB limitou a consulta (429).")
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Resposta PeeringDB inesperada.")
    rows = payload.get("data") or []
    if not rows:
        raise RuntimeError(f"PeeringDB não retornou network para ASN {normalized_asn}.")
    net_row = rows[0] if isinstance(rows[0], dict) else {}
    org_row: dict[str, Any] | None = None
    org_id = net_row.get("org_id")
    if org_id is not None:
        org_response = requests.get(
            f"https://www.peeringdb.com/api/org?id={org_id}",
            timeout=HTTP_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        if org_response.status_code != 429:
            org_response.raise_for_status()
            org_payload = org_response.json()
            if isinstance(org_payload, dict):
                org_rows = org_payload.get("data") or []
                if org_rows and isinstance(org_rows[0], dict):
                    org_row = org_rows[0]
    result = {
        "source": "peeringdb",
        "entity_type": "asn",
        "entity_value": str(normalized_asn),
        "status": "ok",
        "asn": normalized_asn,
        "organization_name": (org_row or {}).get("name") or net_row.get("name"),
        "network_name": net_row.get("name"),
        "aka": net_row.get("aka"),
        "website": net_row.get("website"),
        "looking_glass": net_row.get("looking_glass"),
        "route_server": net_row.get("route_server"),
        "network_type": net_row.get("info_type"),
        "info_type": net_row.get("info_type"),
        "info_prefixes4": net_row.get("info_prefixes4"),
        "info_prefixes6": net_row.get("info_prefixes6"),
        "peering_policy": net_row.get("policy_general"),
        "country": (org_row or {}).get("country"),
        "ix_count": net_row.get("ix_count"),
        "fac_count": net_row.get("fac_count"),
        "raw_data": {"net": net_row, "org": org_row, "payload": payload},
        "fetched_at": _now(),
        "expires_at": _now() + EXTERNAL_CACHE_TTL,
    }
    return result


def get_external_asn_enrichment(asn: int | str, *, conn: psycopg.Connection | None = None) -> dict[str, Any] | None:
    normalized_asn = _normalize_asn(asn)
    row = _fetch_one(
        """
        select
          id,
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
          fetched_at,
          updated_at
        from external_asn_enrichment
        where asn = %s
        limit 1;
        """,
        (normalized_asn,),
        conn=conn,
    )
    return _safe_row(row)


def get_external_ip_enrichment(ip: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any] | None:
    normalized_ip = _normalize_ip(ip)
    row = _fetch_one(
        """
        select
          id,
          ip::text as ip,
          asn,
          organization_name,
          country,
          network_name,
          source,
          confidence,
          raw_data,
          fetched_at,
          updated_at
        from external_ip_enrichment
        where ip = %s::inet
        limit 1;
        """,
        (normalized_ip,),
        conn=conn,
    )
    return _safe_row(row)


def _merge_confidence(*values: str | None) -> str:
    normalized = [str(value).lower() for value in values if value]
    if "confirmed" in normalized:
        return "confirmed"
    if "probable" in normalized:
        return "probable"
    if "suggested" in normalized:
        return "suggested"
    return "unknown"


def _merge_source(*values: str | None) -> str:
    items = [str(value) for value in values if value]
    if not items:
        return "external_enrichment"
    unique = []
    for item in items:
        if item not in unique:
            unique.append(item)
    return "+".join(unique)


def _normalize_asn_enrichment_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    normalized = dict(row)
    normalized["confidence"] = str(normalized.get("confidence") or "suggested")
    return normalized


def enrich_asn(
    asn: int | str,
    *,
    force_refresh: bool = False,
    allow_external: bool = True,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    conn_ctx = conn
    started_at = _now()
    cache_hit = False
    warnings: list[str] = []
    run_id = None
    if conn_ctx is None:
        with get_connection() as fresh_conn:
            run_id = _record_run(
                fresh_conn,
                source="rdap+peeringdb",
                entity_type="asn",
                entity_value=str(normalized_asn),
                status="running",
            )
            try:
                result = enrich_asn(
                    normalized_asn,
                    force_refresh=force_refresh,
                    allow_external=allow_external,
                    conn=fresh_conn,
                )
            except Exception as exc:
                _finish_run(fresh_conn, run_id, status="error", cache_hit=False, error=str(exc))
                raise
            _finish_run(
                fresh_conn,
                run_id,
                status=str(result.get("status") or "ok"),
                cache_hit=bool(result.get("cache_hit")),
                error="; ".join(result.get("warnings") or []) or None,
            )
            return result

    rdap_cache = get_cached_enrichment("rdap", "asn", str(normalized_asn), conn=conn_ctx)
    peeringdb_cache = get_cached_enrichment("peeringdb", "net", str(normalized_asn), conn=conn_ctx)
    rdap_row = None
    peeringdb_row = None

    if rdap_cache is not None and not force_refresh:
        rdap_row = _normalize_asn_enrichment_row(rdap_cache)
        cache_hit = True
    if peeringdb_cache is not None and not force_refresh:
        peeringdb_row = _normalize_asn_enrichment_row(peeringdb_cache)
        cache_hit = True

    if not allow_external and rdap_row is None and peeringdb_row is None:
        return {
            "entity_type": "asn",
            "entity_value": str(normalized_asn),
            "asn": normalized_asn,
            "cache_hit": cache_hit,
            "status": "missing",
            "warnings": ["enriquecimento externo indisponível em cache"],
            "source": "external_enrichment",
            "confidence": "unknown",
            "source_priority": None,
            "organization_name": None,
            "country": None,
            "network_name": None,
            "website": None,
            "looking_glass": None,
            "route_server": None,
            "network_type": None,
            "info_type": None,
            "info_prefixes4": None,
            "info_prefixes6": None,
            "peering_policy": None,
            "raw_data": {},
            "fetched_at": None,
        }

    if allow_external:
        if force_refresh or rdap_row is None:
            try:
                rdap_row = fetch_rdap_asn(normalized_asn)
                save_enrichment_cache(
                    source="rdap",
                    entity_type="asn",
                    entity_value=str(normalized_asn),
                    status="ok",
                    data=rdap_row,
                    expires_at=rdap_row.get("expires_at"),
                    conn=conn_ctx,
                    normalized_asn={
                        "asn": normalized_asn,
                        "source_priority": "rdap",
                        "organization_name": rdap_row.get("organization_name"),
                        "country": rdap_row.get("country"),
                        "network_name": rdap_row.get("network_name"),
                        "website": None,
                        "looking_glass": None,
                        "route_server": None,
                        "network_type": None,
                        "info_type": None,
                        "info_prefixes4": None,
                        "info_prefixes6": None,
                        "peering_policy": None,
                        "source": "rdap",
                        "confidence": "confirmed",
                        "raw_data": rdap_row.get("raw_data") or {},
                        "fetched_at": rdap_row.get("fetched_at"),
                    },
                )
                cache_hit = False
            except Exception as exc:
                warnings.append(f"rdap: {exc}")
                if rdap_row is None and rdap_cache is not None:
                    rdap_row = rdap_cache
                    cache_hit = True
        if force_refresh or peeringdb_row is None:
            try:
                peeringdb_row = fetch_peeringdb_network_by_asn(normalized_asn)
                save_enrichment_cache(
                    source="peeringdb",
                    entity_type="net",
                    entity_value=str(normalized_asn),
                    status="ok",
                    data=peeringdb_row,
                    expires_at=peeringdb_row.get("expires_at"),
                    conn=conn_ctx,
                    normalized_asn={
                        "asn": normalized_asn,
                        "source_priority": "peeringdb>rdap" if rdap_row is not None else "peeringdb",
                        "organization_name": peeringdb_row.get("organization_name"),
                        "country": peeringdb_row.get("country"),
                        "network_name": peeringdb_row.get("network_name"),
                        "website": peeringdb_row.get("website"),
                        "looking_glass": peeringdb_row.get("looking_glass"),
                        "route_server": peeringdb_row.get("route_server"),
                        "network_type": peeringdb_row.get("network_type"),
                        "info_type": peeringdb_row.get("info_type"),
                        "info_prefixes4": peeringdb_row.get("info_prefixes4"),
                        "info_prefixes6": peeringdb_row.get("info_prefixes6"),
                        "peering_policy": peeringdb_row.get("peering_policy"),
                        "source": "peeringdb",
                        "confidence": "confirmed",
                        "raw_data": peeringdb_row.get("raw_data") or {},
                        "fetched_at": peeringdb_row.get("fetched_at"),
                    },
                )
                cache_hit = False
            except Exception as exc:
                warnings.append(f"peeringdb: {exc}")
                if peeringdb_row is None and peeringdb_cache is not None:
                    peeringdb_row = peeringdb_cache
                    cache_hit = True
    else:
        if rdap_row is None and rdap_cache is not None:
            rdap_row = rdap_cache
            cache_hit = True
        if peeringdb_row is None and peeringdb_cache is not None:
            peeringdb_row = peeringdb_cache
            cache_hit = True

    combined_raw = {"rdap": (rdap_row or {}).get("raw_data"), "peeringdb": (peeringdb_row or {}).get("raw_data")}
    country = (peeringdb_row or {}).get("country") or (rdap_row or {}).get("country")
    organization_name = (peeringdb_row or {}).get("organization_name") or (rdap_row or {}).get("organization_name")
    network_name = (peeringdb_row or {}).get("network_name") or (rdap_row or {}).get("network_name")
    website = (peeringdb_row or {}).get("website")
    looking_glass = (peeringdb_row or {}).get("looking_glass")
    route_server = (peeringdb_row or {}).get("route_server")
    network_type = (peeringdb_row or {}).get("network_type") or (peeringdb_row or {}).get("info_type")
    info_type = (peeringdb_row or {}).get("info_type")
    info_prefixes4 = (peeringdb_row or {}).get("info_prefixes4")
    info_prefixes6 = (peeringdb_row or {}).get("info_prefixes6")
    peering_policy = (peeringdb_row or {}).get("peering_policy")
    confidence = "confirmed" if (rdap_row is not None or peeringdb_row is not None) else "unknown"
    source = _merge_source((peeringdb_row or {}).get("source"), (rdap_row or {}).get("source"))
    source_priority = "peeringdb>rdap" if peeringdb_row is not None and rdap_row is not None else ((peeringdb_row or rdap_row or {}).get("source") or "external_enrichment")
    normalized_row = {
        "asn": normalized_asn,
        "source_priority": source_priority,
        "organization_name": organization_name,
        "country": country,
        "network_name": network_name,
        "website": website,
        "looking_glass": looking_glass,
        "route_server": route_server,
        "network_type": network_type,
        "info_type": info_type,
        "info_prefixes4": info_prefixes4,
        "info_prefixes6": info_prefixes6,
        "peering_policy": peering_policy,
        "source": source,
        "confidence": confidence,
        "raw_data": combined_raw,
        "fetched_at": max(
            [row.get("fetched_at") for row in (rdap_row, peeringdb_row) if isinstance(row, dict) and row.get("fetched_at") is not None],
            default=_now(),
        ),
    }
    save_enrichment_cache(
        source="rdap" if rdap_row is not None and peeringdb_row is None else "peeringdb" if peeringdb_row is not None and rdap_row is None else "external",
        entity_type="asn",
        entity_value=str(normalized_asn),
        status="ok" if not warnings else "partial",
        data={
            "asn": normalized_asn,
            "source_priority": source_priority,
            "organization_name": organization_name,
            "country": country,
            "network_name": network_name,
            "website": website,
            "looking_glass": looking_glass,
            "route_server": route_server,
            "network_type": network_type,
            "info_type": info_type,
            "info_prefixes4": info_prefixes4,
            "info_prefixes6": info_prefixes6,
            "peering_policy": peering_policy,
            "source": source,
            "confidence": confidence,
            "raw_data": combined_raw,
            "fetched_at": normalized_row["fetched_at"],
        },
        error="; ".join(warnings) if warnings else None,
        expires_at=normalized_row["fetched_at"] + EXTERNAL_CACHE_TTL if isinstance(normalized_row["fetched_at"], datetime) else _now() + EXTERNAL_CACHE_TTL,
        conn=conn_ctx,
        normalized_asn=normalized_row,
    )
    result = {
        "entity_type": "asn",
        "entity_value": str(normalized_asn),
        "asn": normalized_asn,
        "cache_hit": cache_hit,
        "status": "ok" if not warnings else "partial",
        "warnings": warnings,
        **normalized_row,
    }
    if run_id is not None:
        _finish_run(conn_ctx, run_id, status=result["status"], cache_hit=cache_hit, error="; ".join(warnings) if warnings else None)
    return result


def enrich_ip(
    ip: str,
    *,
    force_refresh: bool = False,
    allow_external: bool = True,
    conn: psycopg.Connection | None = None,
) -> dict[str, Any]:
    normalized_ip = _normalize_ip(ip)
    conn_ctx = conn
    cache_hit = False
    warnings: list[str] = []
    run_id = None
    if conn_ctx is None:
        with get_connection() as fresh_conn:
            run_id = _record_run(
                fresh_conn,
                source="rdap",
                entity_type="ip",
                entity_value=normalized_ip,
                status="running",
            )
            try:
                result = enrich_ip(
                    normalized_ip,
                    force_refresh=force_refresh,
                    allow_external=allow_external,
                    conn=fresh_conn,
                )
            except Exception as exc:
                _finish_run(fresh_conn, run_id, status="error", cache_hit=False, error=str(exc))
                raise
            _finish_run(
                fresh_conn,
                run_id,
                status=str(result.get("status") or "ok"),
                cache_hit=bool(result.get("cache_hit")),
                error="; ".join(result.get("warnings") or []) or None,
            )
            return result

    rdap_cache = get_cached_enrichment("rdap", "ip", normalized_ip, conn=conn_ctx)
    rdap_row = None
    if rdap_cache is not None and not force_refresh:
        rdap_row = rdap_cache
        cache_hit = True

    if not allow_external and rdap_row is None:
        return {
            "entity_type": "ip",
            "entity_value": normalized_ip,
            "ip": normalized_ip,
            "cache_hit": cache_hit,
            "status": "missing",
            "warnings": ["enriquecimento externo indisponível em cache"],
            "source": "external_enrichment",
            "confidence": "unknown",
            "asn": None,
            "organization_name": None,
            "country": None,
            "network_name": None,
            "raw_data": {},
            "fetched_at": None,
        }

    if allow_external:
        if force_refresh or rdap_row is None:
            try:
                rdap_row = fetch_rdap_ip(normalized_ip)
                save_enrichment_cache(
                    source="rdap",
                    entity_type="ip",
                    entity_value=normalized_ip,
                    status="ok",
                    data=rdap_row,
                    expires_at=rdap_row.get("expires_at"),
                    conn=conn_ctx,
                    normalized_ip={
                        "ip": normalized_ip,
                        "asn": rdap_row.get("asn"),
                        "organization_name": rdap_row.get("organization_name"),
                        "country": rdap_row.get("country"),
                        "network_name": rdap_row.get("network_name"),
                        "source": "rdap",
                        "confidence": "confirmed",
                        "raw_data": rdap_row.get("raw_data") or {},
                        "fetched_at": rdap_row.get("fetched_at"),
                    },
                )
                cache_hit = False
            except Exception as exc:
                warnings.append(f"rdap: {exc}")
                if rdap_cache is not None:
                    rdap_row = rdap_cache
                    cache_hit = True
    elif rdap_row is None and rdap_cache is not None:
        rdap_row = rdap_cache
        cache_hit = True

    asn_row = None
    if rdap_row is not None and rdap_row.get("asn") is not None:
        try:
            asn_row = get_external_asn_enrichment(int(rdap_row.get("asn")), conn=conn_ctx)
        except Exception as exc:
            warnings.append(f"asn_lookup: {exc}")
        if allow_external and (force_refresh or asn_row is None):
            try:
                asn_row = enrich_asn(int(rdap_row.get("asn")), force_refresh=force_refresh, allow_external=allow_external, conn=conn_ctx)
            except Exception as exc:
                warnings.append(f"asn_enrich: {exc}")

    confidence = "confirmed" if rdap_row is not None or asn_row is not None else "unknown"
    source = _merge_source((rdap_row or {}).get("source"), (asn_row or {}).get("source"))
    organization_name = (asn_row or {}).get("organization_name") or (rdap_row or {}).get("organization_name")
    country = (asn_row or {}).get("country") or (rdap_row or {}).get("country")
    network_name = (asn_row or {}).get("network_name") or (rdap_row or {}).get("network_name")
    raw_data = {"rdap": (rdap_row or {}).get("raw_data"), "asn": (asn_row or {}).get("raw_data")}
    normalized_row = {
        "ip": normalized_ip,
        "asn": (rdap_row or {}).get("asn") or (asn_row or {}).get("asn"),
        "organization_name": organization_name,
        "country": country,
        "network_name": network_name,
        "source": source,
        "confidence": confidence,
        "raw_data": raw_data,
        "fetched_at": max(
            [row.get("fetched_at") for row in (rdap_row, asn_row) if isinstance(row, dict) and row.get("fetched_at") is not None],
            default=_now(),
        ),
    }
    save_enrichment_cache(
        source="rdap",
        entity_type="ip",
        entity_value=normalized_ip,
        status="ok" if not warnings else "partial",
        data={
            "ip": normalized_ip,
            "asn": normalized_row["asn"],
            "organization_name": organization_name,
            "country": country,
            "network_name": network_name,
            "source": source,
            "confidence": confidence,
            "raw_data": raw_data,
            "fetched_at": normalized_row["fetched_at"],
        },
        error="; ".join(warnings) if warnings else None,
        expires_at=normalized_row["fetched_at"] + EXTERNAL_CACHE_TTL if isinstance(normalized_row["fetched_at"], datetime) else _now() + EXTERNAL_CACHE_TTL,
        conn=conn_ctx,
        normalized_ip=normalized_row,
    )
    result = {
        "entity_type": "ip",
        "entity_value": normalized_ip,
        "cache_hit": cache_hit,
        "status": "ok" if not warnings else "partial",
        "warnings": warnings,
        **normalized_row,
    }
    if run_id is not None:
        _finish_run(conn_ctx, run_id, status=result["status"], cache_hit=cache_hit, error="; ".join(warnings) if warnings else None)
    return result


def list_external_enrichment_runs(*, conn: psycopg.Connection | None = None, limit: int = 50) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          id,
          source,
          entity_type,
          entity_value,
          status,
          cache_hit,
          started_at,
          finished_at,
          error,
          report_path
        from external_enrichment_runs
        order by started_at desc, id desc
        limit %s;
        """,
        (limit,),
        conn=conn,
    )
