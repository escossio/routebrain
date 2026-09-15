from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import os
import re
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.db.connection import get_connection

MAX_LIMIT = 500
DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|senha|token|authorization|bearer|api[_-]?key|openai_api_key|secret|payload|url|query|uri)"
)
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clamp_limit(limit: int | None) -> int:
    if limit is None:
        return 100
    value = int(limit)
    if value < 1:
        raise ValueError("Limite inválido.")
    return min(value, MAX_LIMIT)


def _safe_text(value: Any, *, max_chars: int = 240) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split()).strip()
    if not text:
        return None
    return text[:max_chars]


def normalize_mac(value: Any) -> str | None:
    text = _safe_text(value, max_chars=64)
    if not text:
        return None
    normalized = text.lower().replace("-", ":")
    if _MAC_RE.fullmatch(normalized):
        return normalized
    return None


def normalize_ip(value: Any) -> str | None:
    text = _safe_text(value, max_chars=80)
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    return str(address)


def is_internal_inventory_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or getattr(address, "is_site_local", False)
    )


def sanitize_raw_summary(value: Any) -> Any:
    if isinstance(value, list):
        return [sanitize_raw_summary(item) for item in value[:50]]
    if not isinstance(value, dict):
        if isinstance(value, str) and ("?" in value or "://" in value):
            return "[redigido]"
        return value
    clean: dict[str, Any] = {}
    for key, item in value.items():
        key_text = str(key)
        if _SENSITIVE_KEY_RE.search(key_text):
            continue
        if isinstance(item, str) and ("?" in item or "://" in item) and _SENSITIVE_KEY_RE.search(item):
            clean[key_text] = "[redigido]"
            continue
        clean[key_text[:80]] = sanitize_raw_summary(item)
    return clean


def _candidate_uid(*, ip: str | None, mac: str | None, hostname: str | None, source: str) -> str:
    identity = mac or ip or (hostname or "").lower() or source
    digest = hashlib.sha1(f"{source}|{identity}".encode("utf-8")).hexdigest()[:20]
    return f"ihc_{digest}"


def _candidate_identity(candidate: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    return (
        normalize_ip(candidate.get("ip")),
        normalize_mac(candidate.get("mac")),
        _safe_text(candidate.get("hostname"), max_chars=160),
    )


def calculate_candidate_confidence(candidate: dict[str, Any]) -> tuple[float, list[str]]:
    ip, mac, hostname = _candidate_identity(candidate)
    evidence_types = set(candidate.get("evidence_types") or [])
    source = str(candidate.get("source") or "")
    score = 0.0
    reasons: list[str] = []
    if "neighbor" in evidence_types or source == "neighbor":
        score = max(score, 0.90)
        reasons.append("neighbor_identity_platform_interface")
    if "dhcp_lease" in evidence_types or source == "dhcp_lease":
        if ip and mac and hostname:
            score = max(score, 0.85)
            reasons.append("dhcp_hostname_mac_ip")
        elif ip and mac:
            score = max(score, 0.75)
            reasons.append("dhcp_mac_ip")
    if ("arp" in evidence_types or source == "arp") and ip and mac:
        score = max(score, 0.60)
        reasons.append("arp_ip_mac")
    if ("bridge_host" in evidence_types or source == "bridge_host") and mac and candidate.get("interface_name"):
        score = max(score, 0.60)
        reasons.append("bridge_mac_interface")
    if {"arp", "bridge_host"} <= evidence_types and ip and mac:
        score = max(score, 0.70)
        reasons.append("arp_bridge_convergence")
    if ("dns_cache" in evidence_types or source == "dns_cache") and ip and hostname:
        score = max(score, 0.45)
        reasons.append("dns_hostname_ip")
    if "traceroute_hop" in evidence_types and ip:
        score = max(score, 0.30)
        reasons.append("traceroute_hop_ip_only")
    if ip and mac and hostname and len(evidence_types) >= 2:
        score = min(0.95, max(score, 0.88))
        reasons.append("multiple_sources_hostname_mac_ip")
    if not score and ip:
        score = 0.30
        reasons.append("ip_only")
    if not score and mac:
        score = 0.25
        reasons.append("mac_only")
    return round(score, 2), reasons[:8]


def start_discovery_run(source: str, mode: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    run_uid = f"ihd_{os.urandom(8).hex()}"
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    insert into inventory_discovery_runs (run_uid, source, mode, status, metadata)
                    values (%s, %s, %s, 'running', %s)
                    returning *;
                    """,
                    (run_uid, source, mode, Jsonb(sanitize_raw_summary(metadata or {}))),
                )
                row = cur.fetchone()
            conn.commit()
        return dict(row)
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def finish_discovery_run(
    run_uid: str,
    status: str,
    counters: dict[str, Any],
    *,
    error_message: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    update inventory_discovery_runs
                    set status = %s,
                        finished_at = now(),
                        raw_seen = %s,
                        candidates_seen = %s,
                        inserted = %s,
                        updated = %s,
                        skipped = %s,
                        error_message = %s,
                        metadata = coalesce(metadata, '{}'::jsonb) || %s
                    where run_uid = %s
                    returning *;
                    """,
                    (
                        status,
                        int(counters.get("raw_seen") or 0),
                        int(counters.get("candidates_seen") or 0),
                        int(counters.get("inserted") or 0),
                        int(counters.get("updated") or 0),
                        int(counters.get("skipped") or 0),
                        _safe_text(error_message, max_chars=400),
                        Jsonb(sanitize_raw_summary(metadata or {})),
                        run_uid,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return dict(row) if row else {}
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def upsert_host_candidate(candidate: dict[str, Any], *, run_uid: str | None = None) -> tuple[dict[str, Any], bool]:
    ip, mac, hostname = _candidate_identity(candidate)
    if ip and not is_internal_inventory_ip(ip):
        raise ValueError("IP não é interno para inventário.")
    if not any((ip, mac, hostname)):
        raise ValueError("Candidato sem IP, MAC ou hostname.")
    source = _safe_text(candidate.get("source"), max_chars=40) or "manual"
    evidence_types = candidate.get("evidence_types") if isinstance(candidate.get("evidence_types"), list) else []
    confidence, reasons = calculate_candidate_confidence({**candidate, "ip": ip, "mac": mac, "hostname": hostname, "evidence_types": evidence_types})
    candidate_uid = candidate.get("candidate_uid") or _candidate_uid(ip=ip, mac=mac, hostname=hostname, source=source)
    metadata = sanitize_raw_summary(candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {})
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    insert into inventory_host_candidates (
                        candidate_uid, source, source_detail, ip, mac, hostname, interface_name,
                        interface_mac, vlan, site_code, vendor, device_type, confidence,
                        confidence_reason, metadata
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    on conflict (candidate_uid) do update
                    set last_seen_at = now(),
                        source_detail = coalesce(excluded.source_detail, inventory_host_candidates.source_detail),
                        ip = coalesce(excluded.ip, inventory_host_candidates.ip),
                        mac = coalesce(excluded.mac, inventory_host_candidates.mac),
                        hostname = coalesce(excluded.hostname, inventory_host_candidates.hostname),
                        interface_name = coalesce(excluded.interface_name, inventory_host_candidates.interface_name),
                        interface_mac = coalesce(excluded.interface_mac, inventory_host_candidates.interface_mac),
                        vlan = coalesce(excluded.vlan, inventory_host_candidates.vlan),
                        site_code = coalesce(excluded.site_code, inventory_host_candidates.site_code),
                        vendor = coalesce(excluded.vendor, inventory_host_candidates.vendor),
                        device_type = coalesce(excluded.device_type, inventory_host_candidates.device_type),
                        confidence = greatest(inventory_host_candidates.confidence, excluded.confidence),
                        confidence_reason = excluded.confidence_reason,
                        metadata = coalesce(inventory_host_candidates.metadata, '{}'::jsonb) || excluded.metadata
                    returning *, (xmax = 0) as inserted_now;
                    """,
                    (
                        candidate_uid,
                        source,
                        _safe_text(candidate.get("source_detail"), max_chars=120),
                        ip,
                        mac,
                        hostname,
                        _safe_text(candidate.get("interface_name"), max_chars=120),
                        normalize_mac(candidate.get("interface_mac")),
                        _safe_text(candidate.get("vlan"), max_chars=40),
                        _safe_text(candidate.get("site_code"), max_chars=80),
                        _safe_text(candidate.get("vendor"), max_chars=120),
                        _safe_text(candidate.get("device_type"), max_chars=120),
                        confidence,
                        Jsonb(reasons),
                        Jsonb(metadata),
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        data = dict(row)
        inserted = bool(data.pop("inserted_now", False))
        return data, inserted
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def add_candidate_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    ip = normalize_ip(evidence.get("ip"))
    if ip and not is_internal_inventory_ip(ip):
        raise ValueError("IP não é interno para evidência de inventário.")
    raw_summary = sanitize_raw_summary(evidence.get("raw_summary") if isinstance(evidence.get("raw_summary"), dict) else {})
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    insert into inventory_host_candidate_evidence (
                        candidate_uid, run_uid, evidence_type, ip, mac, hostname, interface_name, raw_summary
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s)
                    returning *;
                    """,
                    (
                        evidence["candidate_uid"],
                        evidence["run_uid"],
                        evidence["evidence_type"],
                        ip,
                        normalize_mac(evidence.get("mac")),
                        _safe_text(evidence.get("hostname"), max_chars=160),
                        _safe_text(evidence.get("interface_name"), max_chars=120),
                        Jsonb(raw_summary),
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        return dict(row)
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def ingest_discovery_candidates(
    candidates: list[dict[str, Any]],
    *,
    source: str,
    mode: str,
    dry_run: bool,
    run_uid: str | None = None,
) -> dict[str, Any]:
    counters = {"raw_seen": len(candidates), "candidates_seen": 0, "inserted": 0, "updated": 0, "skipped": 0}
    preview: list[dict[str, Any]] = []
    for raw in candidates:
        try:
            ip, mac, hostname = _candidate_identity(raw)
            if ip and not is_internal_inventory_ip(ip):
                counters["skipped"] += 1
                continue
            normalized = {
                **raw,
                "source": raw.get("source") or source,
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
            }
            evidence_type = str(raw.get("evidence_type") or raw.get("source_detail") or source)
            evidence_types = [evidence_type]
            normalized["evidence_types"] = evidence_types
            confidence, reasons = calculate_candidate_confidence(normalized)
            candidate_uid = _candidate_uid(ip=ip, mac=mac, hostname=hostname, source=str(normalized["source"]))
            normalized["candidate_uid"] = candidate_uid
            normalized["confidence"] = confidence
            normalized["confidence_reason"] = reasons
            counters["candidates_seen"] += 1
            if dry_run:
                preview.append({k: normalized.get(k) for k in ("candidate_uid", "source", "source_detail", "ip", "mac", "hostname", "interface_name", "confidence", "confidence_reason")})
                continue
            candidate, inserted = upsert_host_candidate(normalized, run_uid=run_uid)
            add_candidate_evidence(
                {
                    "candidate_uid": candidate["candidate_uid"],
                    "run_uid": run_uid,
                    "evidence_type": evidence_type if evidence_type in {"arp", "dhcp_lease", "dns_cache", "bridge_host", "neighbor", "interface", "traceroute_hop", "manual"} else "manual",
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "interface_name": normalized.get("interface_name"),
                    "raw_summary": normalized.get("metadata") or {},
                }
            )
            counters["inserted" if inserted else "updated"] += 1
            preview.append({k: candidate.get(k) for k in ("candidate_uid", "source", "source_detail", "ip", "mac", "hostname", "interface_name", "confidence", "confidence_reason", "status")})
        except Exception:
            counters["skipped"] += 1
            continue
    return {"counters": counters, "preview": preview[:50]}


def list_discovery_runs(limit: int = 50) -> list[dict[str, Any]]:
    limit = _clamp_limit(limit)
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    select *
                    from inventory_discovery_runs
                    order by started_at desc
                    limit %s;
                    """,
                    (limit,),
                )
                return [dict(row) for row in cur.fetchall()]
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def list_host_candidates(status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    limit = _clamp_limit(limit)
    params: list[Any] = []
    where = "1 = 1"
    if status:
        where += " and status = %s"
        params.append(status)
    params.append(limit)
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    f"""
                    select *
                    from inventory_host_candidates
                    where {where}
                    order by confidence desc, last_seen_at desc
                    limit %s;
                    """,
                    tuple(params),
                )
                return [dict(row) for row in cur.fetchall()]
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def get_host_candidate(candidate_uid: str) -> dict[str, Any] | None:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("select * from inventory_host_candidates where candidate_uid = %s limit 1;", (candidate_uid,))
                candidate = cur.fetchone()
                if candidate is None:
                    return None
                cur.execute(
                    """
                    select *
                    from inventory_host_candidate_evidence
                    where candidate_uid = %s
                    order by observed_at desc
                    limit 100;
                    """,
                    (candidate_uid,),
                )
                evidence = [dict(row) for row in cur.fetchall()]
        data = dict(candidate)
        data["evidence"] = evidence
        return data
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def promote_candidate_to_inventory(
    candidate_uid: str,
    site_code: str | None = None,
    confirm: bool = False,
    user: str | None = None,
) -> dict[str, Any]:
    if not confirm:
        raise ValueError("Promoção de candidato exige confirm=true.")
    candidate = get_host_candidate(candidate_uid)
    if candidate is None:
        raise ValueError("Candidato não encontrado.")
    if candidate.get("status") == "promoted" and candidate.get("promoted_host_id"):
        return {"status": "already_promoted", "host_id": candidate.get("promoted_host_id"), "candidate": candidate}
    hostname = _safe_text(candidate.get("hostname"), max_chars=120) or f"host-{candidate_uid[-8:]}"
    mgmt_ip = normalize_ip(candidate.get("ip"))
    site_id = None
    if site_code:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("select id from inventory_sites where site_code = %s limit 1;", (site_code,))
                site = cur.fetchone()
                if site is None:
                    raise ValueError("Site não encontrado.")
                site_id = site["id"]
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    insert into inventory_hosts (hostname, mgmt_ip, site_id, role, vendor, model, os_name, status, notes)
                    values (%s, %s, %s, %s, %s, %s, %s, 'candidate-promoted', %s)
                    on conflict (hostname) do update
                    set mgmt_ip = coalesce(excluded.mgmt_ip, inventory_hosts.mgmt_ip),
                        site_id = coalesce(excluded.site_id, inventory_hosts.site_id),
                        vendor = coalesce(excluded.vendor, inventory_hosts.vendor),
                        updated_at = now()
                    returning id, hostname, mgmt_ip::text, site_id, status;
                    """,
                    (
                        hostname,
                        mgmt_ip,
                        site_id,
                        _safe_text(candidate.get("device_type"), max_chars=80) or "unknown",
                        _safe_text(candidate.get("vendor"), max_chars=120),
                        None,
                        None,
                        f"Promovido de candidato {candidate_uid}. Fonte={candidate.get('source')}. Usuário={_safe_text(user, max_chars=80) or 'unknown'}.",
                    ),
                )
                host = dict(cur.fetchone())
                if candidate.get("interface_name"):
                    cur.execute(
                        """
                        insert into inventory_interfaces (host_id, interface_name, interface_ip, vlan, status, notes)
                        values (%s, %s, %s, %s, 'candidate-promoted', %s)
                        on conflict (host_id, interface_name) do update
                        set interface_ip = coalesce(excluded.interface_ip, inventory_interfaces.interface_ip),
                            vlan = coalesce(excluded.vlan, inventory_interfaces.vlan),
                            updated_at = now();
                        """,
                        (
                            host["id"],
                            candidate.get("interface_name"),
                            mgmt_ip,
                            candidate.get("vlan"),
                            f"Interface sugerida por discovery candidate {candidate_uid}.",
                        ),
                    )
                cur.execute(
                    """
                    update inventory_host_candidates
                    set status = 'promoted',
                        promoted_host_id = %s,
                        last_seen_at = now()
                    where candidate_uid = %s;
                    """,
                    (host["id"], candidate_uid),
                )
            conn.commit()
        return {"status": "promoted", "host": host, "candidate_uid": candidate_uid}
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def ignore_candidate(candidate_uid: str, reason: str | None = None, confirm: bool = False) -> dict[str, Any]:
    if not confirm:
        raise ValueError("Ignorar candidato exige confirm=true.")
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    update inventory_host_candidates
                    set status = 'ignored',
                        metadata = coalesce(metadata, '{}'::jsonb) || %s,
                        last_seen_at = now()
                    where candidate_uid = %s
                    returning *;
                    """,
                    (Jsonb({"ignore_reason": _safe_text(reason, max_chars=240)}), candidate_uid),
                )
                row = cur.fetchone()
            conn.commit()
        if row is None:
            raise ValueError("Candidato não encontrado.")
        return dict(row)
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def discovery_summary() -> dict[str, Any]:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    select
                      (select count(*) from inventory_hosts)::bigint as confirmed_hosts,
                      (select count(*) from inventory_host_candidates where status = 'candidate')::bigint as candidates,
                      (select count(*) from inventory_host_candidates where status = 'candidate' and confidence >= 0.80)::bigint as high_confidence_candidates,
                      (select count(*) from inventory_host_candidates where status = 'candidate' and hostname is null)::bigint as candidates_without_hostname,
                      (select max(started_at)::text from inventory_discovery_runs)::text as last_discovery_at,
                      coalesce((select jsonb_agg(distinct source) from inventory_host_candidates), '[]'::jsonb) as sources;
                    """
                )
                row = cur.fetchone()
        return dict(row) if row else {}
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def lookup_inventory_context_by_ip(ip: str) -> dict[str, Any]:
    normalized_ip = normalize_ip(ip)
    if not normalized_ip:
        raise ValueError("IP inválido.")
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    select
                      h.id,
                      h.hostname,
                      h.mgmt_ip::text as mgmt_ip,
                      h.role,
                      h.vendor,
                      h.model,
                      h.status,
                      s.site_code,
                      s.name as site_name,
                      i.interface_name,
                      i.interface_ip::text as interface_ip,
                      i.description as interface_description
                    from inventory_hosts h
                    left join inventory_sites s on s.id = h.site_id
                    left join inventory_interfaces i
                      on i.host_id = h.id
                     and i.interface_ip = %s::inet
                    where h.mgmt_ip = %s::inet
                       or i.interface_ip = %s::inet
                    order by (h.mgmt_ip = %s::inet) desc, h.hostname
                    limit 5;
                    """,
                    (normalized_ip, normalized_ip, normalized_ip, normalized_ip),
                )
                hosts = [dict(row) for row in cur.fetchall()]
                cur.execute(
                    """
                    select
                      candidate_uid,
                      source,
                      source_detail,
                      ip::text as ip,
                      mac,
                      hostname,
                      interface_name,
                      site_code,
                      confidence,
                      confidence_reason,
                      status,
                      last_seen_at
                    from inventory_host_candidates
                    where ip = %s::inet
                    order by status = 'candidate' desc, confidence desc, last_seen_at desc
                    limit 10;
                    """,
                    (normalized_ip,),
                )
                candidates = [dict(row) for row in cur.fetchall()]
        return {
            "ip": normalized_ip,
            "status": "confirmed" if hosts else "candidate" if candidates else "unknown",
            "hosts": hosts,
            "candidates": candidates,
        }
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc
