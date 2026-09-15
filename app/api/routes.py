from __future__ import annotations

import ipaddress
import mimetypes
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import psycopg
import requests
from fastapi import APIRouter, HTTPException, Path as FastAPIPath, Query, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from psycopg.rows import dict_row

from app.api.public_review import (
    PUBLIC_REVIEW_BLOCKED_MESSAGE,
    is_public_review_mode,
    public_review_client_config,
    sanitize_public_payload,
)
from app.api.auth import auth_payload_for_request, get_current_user, is_admin
from app.api.schemas import (
    HealthResponse,
    ExternalRoutesEnrichRequest,
    ExternalRoutesIngestRequest,
    ExternalRoutesTraceRequest,
    InventoryCandidateIgnoreRequest,
    InventoryCandidatePromoteRequest,
    InventoryDiscoveryCollectRequest,
    LearningRequestCreate,
    LearningRequestEnrich,
    LearningRequestExecute,
    QuestionAskRequest,
    QuestionActionRequest,
    QuestionExecuteActiveRequest,
    QuestionSpeechRequest,
    QuestionSpeechResponse,
    RouteLearningCloudflareDedicatedRunRequest,
    SemanticRebuildRequest,
    SummaryResponse,
)
from app.db.connection import get_connection
from app.services.bgp_operational_queries import (
    get_asn_lookup,
    get_peer_lookup,
    get_prefix_lookup,
    lookup_bgp_by_ip,
    get_top_changes,
    get_top_origin_asns,
    get_top_peers,
    get_top_prefixes,
)
from app.services.bgp_visibility import build_bgp_visibility_response
from app.services.inventory_queries import (
    get_host,
    get_site,
    list_hosts,
    list_hosts_by_site,
    list_peer_links,
    list_sites,
    list_unmatched_bgp_peers,
    search_hosts,
)
from app.services.inventory_discovery import (
    discovery_summary,
    get_host_candidate,
    ignore_candidate,
    list_discovery_runs,
    list_host_candidates,
    promote_candidate_to_inventory,
)
from app.services.ixbr_discovery_queries import (
    get_inventory_public_context,
    get_ixbr_participant,
    list_ixbr_asns_seen_as_origin,
    list_ixbr_locations,
    list_ixbr_participants,
    list_ixbr_participants_without_bgp_origin,
    summarize_ixbr_vs_bgp,
)
from app.services.external_enrichment import (
    enrich_asn,
    enrich_ip,
    get_cached_enrichment,
    get_external_asn_enrichment,
    get_external_ip_enrichment,
)
from app.services.external_route_inventory import (
    compare_service_routes,
    enrich_external_hop,
    get_external_hop_context,
    get_external_route_trace_graph,
    get_external_hop,
    get_service_route_summary,
    ingest_existing_traceroutes,
    list_external_hops,
    list_external_route_edges,
    list_external_services,
    rebuild_service_hop_summary,
    run_cloudflare_dedicated_trace,
    run_external_route_service_trace,
    seed_external_services,
)
from app.services.mikrotik_observer import collect_mikrotik_host_inventory, collect_mikrotik_observed_destinations
from app.services.observed_destinations import (
    categories_summary,
    build_observed_destination_report,
    get_observed_destination_baseline,
    enrich_pending_observed_destinations,
    get_observed_destination,
    list_observed_destination_baselines,
    list_unenriched_observed_destinations,
    list_top_observed_asns,
    list_top_observed_destinations,
    promote_observed_destination_to_baseline,
    summarize_observed_destinations_ui,
)
from app.services.observed_destination_baselines import (
    execute_baseline_active_measurement,
    get_baseline_measurements,
    get_baseline_traceroute_graph,
)
from app.services.route_graph import (
    build_global_route_graph,
    build_private_path_graph,
    build_service_route_graph,
    compare_route_graph_services,
    get_route_graph_hop_context,
    list_route_graph_clusters,
    list_unknown_route_graph_hops,
)
from app.services.route_learning_builder import build_cloudflare_post_change_run_plans
from app.services.route_learning_builder import build_learning_comparison_plan
from app.services.route_learning_builder import build_route_learning_visual_payload
from app.services.route_learning_builder import build_route_profile
from app.services.route_learning_builder import build_temporal_profile_comparison
from app.services.route_learning_demo import get_route_learning_demo_payload
from app.services.route_memory_sdk import (
    build_grafana_divergence_rows,
    build_grafana_edge_rows,
    build_grafana_node_rows,
    build_grafana_summary,
    load_graph_snapshot_by_uid,
    load_latest_graph_snapshot,
)
from app.services.route_memory_persistence import fetch_latest_route_memory_graph_snapshot, fetch_route_memory_graph_snapshot
from app.services.observed_destination_trends import (
    get_asn_trends,
    get_category_trends,
    get_observed_destination_trend,
    get_top_destination_trends,
    summarize_observed_destination_trends,
)
from app.services.learning_classifier import classify_learning_request, get_classifications_for_entity, get_request_classifications, list_known_networks
from app.services.learning_memory import get_learning_memory_for_domain, summarize_learning_memory
from app.services.semantic_memory import (
    get_semantic_document,
    learning_search,
    list_semantic_documents,
    rebuild_semantic_documents,
    semantic_healthcheck,
    semantic_search,
)
from app.services.learning_orchestrator import (
    approve_learning_request,
    build_answer,
    create_learning_request,
    enrich_learning_request,
    execute_learning_request,
    get_learning_request,
    list_learning_requests,
)
from app.services.questions import (
    approve_question_active,
    ask_question_compact,
    build_speech_text_from_question_response,
    execute_question_active,
    execute_question_action,
    get_question_action_plan,
    get_question_active_plan,
    get_question_compact,
    list_recent_questions_compact,
)
from app.services.tts_client import generate_question_audio, get_tts_health, get_tts_config, is_tts_enabled
from app.services.tts_client import extract_audio_filename
from app.services.traceroute_graph import get_traceroute_graph_by_run, get_traceroute_graph_for_learning_request
from app.api.route_graph import router as route_graph_router

router = APIRouter()
router.include_router(route_graph_router)

_DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."
_STATIC_DIR = Path(__file__).resolve().parents[1] / "static"


@router.get("/")
def root() -> FileResponse:
    html_path = _STATIC_DIR / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return FileResponse(html_path)


def _fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
    except psycopg.Error as exc:
        raise HTTPException(status_code=500, detail=_DB_ERROR_MESSAGE) from exc


def _fetch_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                row = cur.fetchone()
                return dict(row) if row is not None else None
    except psycopg.Error as exc:
        raise HTTPException(status_code=500, detail=_DB_ERROR_MESSAGE) from exc


def _fetch_scalar(sql: str, params: tuple[Any, ...] = ()) -> Any:
    row = _fetch_one(sql, params)
    if not row:
        return None
    return next(iter(row.values()))


def _validate_prefix(prefix: str) -> str:
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Prefixo inválido.") from exc
    return str(network)


def _validate_peer_ip(peer_ip: str) -> str:
    try:
        return str(ipaddress.ip_address(peer_ip))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="IP de peer inválido.") from exc


def _normalize_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value
    path = parsed.path or "/"
    if path == "":
        path = "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))


def _raise_operational_error(exc: ValueError) -> None:
    raise HTTPException(status_code=400, detail=str(exc)) from exc


def _raise_not_found(message: str = "Nenhum dado encontrado.") -> None:
    raise HTTPException(status_code=404, detail=message)


def _call_operational_query(func, *args, **kwargs):
    try:
        result = func(*args, **kwargs)
    except ValueError as exc:
        _raise_operational_error(exc)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if result is None:
        _raise_not_found()
    return result


def _call_learning_query(func, *args, **kwargs):
    try:
        result = func(*args, **kwargs)
    except ValueError as exc:
        _raise_operational_error(exc)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if result is None:
        _raise_not_found()
    return result


def _call_question_query(func, *args, **kwargs):
    try:
        result = func(*args, **kwargs)
    except ValueError as exc:
        _raise_operational_error(exc)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if result is None:
        _raise_not_found("Pergunta não encontrada.")
    return result


def _question_error_payload(error_code: str, message: str, details: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "error",
        "error_code": error_code,
        "message": message,
    }
    if details:
        payload["details"] = details
    return payload


def _validate_audio_filename(filename: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.(wav|mp3|ogg)", filename or ""):
        raise HTTPException(status_code=400, detail="Nome de arquivo de áudio inválido.")
    if "/" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Nome de arquivo de áudio inválido.")
    return filename


def _compose_asn_enrichment_view(asn: int, *, refresh: bool = False) -> dict[str, Any] | None:
    normalized_asn = int(asn)
    if refresh:
        return enrich_asn(normalized_asn, force_refresh=True, allow_external=True)

    rdap_cache = get_cached_enrichment("rdap", "asn", str(normalized_asn))
    peeringdb_cache = get_cached_enrichment("peeringdb", "asn", str(normalized_asn))
    normalized = get_external_asn_enrichment(normalized_asn)
    if normalized is None and rdap_cache is None and peeringdb_cache is None:
        return None
    return {
        "entity_type": "asn",
        "entity_value": str(normalized_asn),
        "cache_hit": bool(rdap_cache or peeringdb_cache),
        "status": (normalized or rdap_cache or peeringdb_cache or {}).get("status", "ok"),
        "freshness": (normalized or rdap_cache or peeringdb_cache or {}).get("freshness"),
        "cache": {
            "rdap": rdap_cache,
            "peeringdb": peeringdb_cache,
        },
        "normalized": normalized,
        "summary_text": (
            normalized.get("organization_name")
            if isinstance(normalized, dict) and normalized.get("organization_name")
            else "Enriquecimento ASN disponível em cache."
        ),
    }


def _compose_ip_enrichment_view(ip: str, *, refresh: bool = False) -> dict[str, Any] | None:
    try:
        normalized_ip = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="IP inválido.") from exc
    if refresh:
        return enrich_ip(normalized_ip, force_refresh=True, allow_external=True)

    rdap_cache = get_cached_enrichment("rdap", "ip", normalized_ip)
    normalized = get_external_ip_enrichment(normalized_ip)
    if normalized is None and rdap_cache is None:
        return None
    return {
        "entity_type": "ip",
        "entity_value": normalized_ip,
        "cache_hit": bool(rdap_cache),
        "status": (normalized or rdap_cache or {}).get("status", "ok"),
        "freshness": (normalized or rdap_cache or {}).get("freshness"),
        "cache": {
            "rdap": rdap_cache,
        },
        "normalized": normalized,
        "summary_text": (
            normalized.get("organization_name")
            if isinstance(normalized, dict) and normalized.get("organization_name")
            else "Enriquecimento IP disponível em cache."
        ),
    }


@router.get("/health", response_model=HealthResponse)
def health() -> dict[str, str]:
    return {"status": "ok", "service": "routebrain-api"}


@router.get("/auth/me")
def auth_me(request: Request) -> dict[str, Any]:
    return auth_payload_for_request(request)


@router.get("/public-review/config")
def public_review_config() -> dict[str, Any]:
    return public_review_client_config()


@router.get("/summary", response_model=SummaryResponse)
def summary() -> dict[str, Any]:
    raw_count_row = _fetch_one("select count(*)::bigint as value from bgp_raw_routes;")
    current_count_row = _fetch_one("select count(*)::bigint as value from bgp_current_routes;")
    change_count_row = _fetch_one("select count(*)::bigint as value from bgp_route_changes;")
    enrichment_summary = _fetch_one("select * from v_bgp_enrichment_summary;") or {}
    current_summary = _fetch_one("select * from v_bgp_current_summary;") or {}
    change_summary = _fetch_one("select * from v_bgp_change_summary;") or {}
    ping_enrichment_summary = _fetch_one("select * from v_bgp_ping_enrichment_summary;") or {}
    active_ping_count = _fetch_scalar("select count(*)::bigint as value from active_ping_measurements;")
    active_traceroute_measurement_count = _fetch_scalar(
        "select count(*)::bigint as value from active_traceroute_measurements;"
    )
    active_traceroute_hop_count = _fetch_scalar("select count(*)::bigint as value from active_traceroute_hops;")
    traceroute_summary_count_targets = _fetch_scalar(
        "select count(*)::bigint as value from v_active_traceroute_summary_by_target;"
    )
    traceroute_hop_summary = _fetch_one("select * from v_active_traceroute_hop_summary;")
    traceroute_classification_summary = _fetch_one("select * from v_active_traceroute_classification_summary;")
    synthetic_runs_count = _fetch_scalar("select count(*)::bigint as value from synthetic_browser_runs;")
    synthetic_hosts_count = _fetch_scalar("select count(*)::bigint as value from synthetic_browser_hosts;")
    synthetic_ip_measurements_count = _fetch_scalar(
        "select count(*)::bigint as value from synthetic_browser_ip_measurements;"
    )
    latest_synthetic = _fetch_one(
        """
        select
          run_id,
          url,
          final_url,
          title,
          analyzed_at,
          total_ips_measured,
          ping_success,
          avg_rtt_avg_ms,
          traceroute_success,
          ips_with_bgp_match
        from v_synthetic_browser_latest_domain_report
        order by analyzed_at desc, run_id desc
        limit 1;
        """
    )

    return {
        "bgp_raw_routes": int(raw_count_row["value"]) if raw_count_row else 0,
        "bgp_current_routes": int(current_count_row["value"]) if current_count_row else 0,
        "bgp_route_changes": int(change_count_row["value"]) if change_count_row else 0,
        "enrichment_summary": enrichment_summary,
        "current_summary": current_summary,
        "change_summary": change_summary,
        "ping_enrichment_summary": ping_enrichment_summary,
        "active_ping_count": int(active_ping_count) if active_ping_count is not None else 0,
        "active_traceroute_measurement_count": int(active_traceroute_measurement_count)
        if active_traceroute_measurement_count is not None
        else 0,
        "active_traceroute_hop_count": int(active_traceroute_hop_count) if active_traceroute_hop_count is not None else 0,
        "traceroute_summary_count_targets": int(traceroute_summary_count_targets)
        if traceroute_summary_count_targets is not None
        else 0,
        "traceroute_hop_summary": traceroute_hop_summary,
        "traceroute_classification_summary": traceroute_classification_summary,
        "synthetic_summary": {
            "synthetic_browser_runs_count": int(synthetic_runs_count) if synthetic_runs_count is not None else 0,
            "synthetic_browser_hosts_count": int(synthetic_hosts_count) if synthetic_hosts_count is not None else 0,
            "synthetic_browser_ip_measurements_count": int(synthetic_ip_measurements_count)
            if synthetic_ip_measurements_count is not None
            else 0,
            "latest_synthetic_run_id": latest_synthetic.get("run_id") if latest_synthetic else None,
            "latest_synthetic_url": latest_synthetic.get("url") if latest_synthetic else None,
            "latest_synthetic_analyzed_at": latest_synthetic.get("analyzed_at") if latest_synthetic else None,
            "latest_synthetic_total_ips_measured": latest_synthetic.get("total_ips_measured")
            if latest_synthetic
            else None,
            "latest_synthetic_ping_success": latest_synthetic.get("ping_success") if latest_synthetic else None,
            "latest_synthetic_avg_rtt_avg_ms": latest_synthetic.get("avg_rtt_avg_ms")
            if latest_synthetic
            else None,
            "latest_synthetic_traceroute_success": latest_synthetic.get("traceroute_success")
            if latest_synthetic
            else None,
            "latest_synthetic_ips_with_bgp_match": latest_synthetic.get("ips_with_bgp_match")
            if latest_synthetic
            else None,
        },
    }


@router.get("/changes/latest")
def latest_changes(limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          detected_at,
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          change_type,
          old_as_path,
          new_as_path,
          old_next_hop::text as old_next_hop,
          new_next_hop::text as new_next_hop,
          old_origin_asn,
          new_origin_asn,
          inventory_peer_name,
          inventory_connection_type,
          ixp_name,
          router_hostname,
          enrichment_status
        from v_bgp_route_changes_enriched
        order by detected_at desc
        limit %s;
        """,
        (limit,),
    )


def _prefix_current_rows(prefix_value: str) -> list[dict[str, Any]]:
    normalized = _validate_prefix(prefix_value)
    return _fetch_all(
        """
        select
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          next_hop::text as next_hop,
          as_path,
          origin_asn,
          origin_type,
          first_seen,
          last_seen,
          inventory_peer_name,
          inventory_connection_type,
          inventory_peer_status,
          router_hostname,
          router_role,
          interface_name,
          interface_description,
          ixp_name,
          site_name,
          enrichment_status,
          ping_status,
          packet_loss_percent,
          rtt_avg_ms,
          rtt_max_ms,
          ping_measured_at
        from v_bgp_current_routes_with_ping
        where prefix = %s::cidr
        order by peer_ip::text, collector;
        """,
        (normalized,),
    )


def _prefix_change_rows(prefix_value: str, limit: int = 20) -> list[dict[str, Any]]:
    normalized = _validate_prefix(prefix_value)
    return _fetch_all(
        """
        select
          detected_at,
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          change_type,
          old_as_path,
          new_as_path,
          old_next_hop::text as old_next_hop,
          new_next_hop::text as new_next_hop,
          old_origin_asn,
          new_origin_asn,
          inventory_peer_name,
          inventory_connection_type,
          ixp_name,
          router_hostname,
          enrichment_status,
          ping_status,
          packet_loss_percent,
          rtt_avg_ms,
          rtt_max_ms,
          ping_measured_at
        from v_bgp_route_changes_with_ping
        where prefix = %s::cidr
        order by detected_at desc
        limit %s;
        """,
        (normalized, limit),
    )


@router.get("/prefix")
def prefix_query(q: str = Query(..., min_length=1), limit: int = Query(20, ge=1, le=200)) -> dict[str, Any]:
    normalized = _validate_prefix(q)
    return {
        "prefix": normalized,
        "current_routes": _prefix_current_rows(normalized),
        "recent_changes": _prefix_change_rows(normalized, limit=limit),
    }


@router.get("/prefix/{prefix:path}")
def prefix_path(prefix: str = FastAPIPath(..., description="Prefixo CIDR, por exemplo 192.0.2.0/32")) -> dict[str, Any]:
    normalized = _validate_prefix(prefix)
    return {
        "prefix": normalized,
        "current_routes": _prefix_current_rows(normalized),
        "recent_changes": _prefix_change_rows(normalized),
    }


@router.get("/peer/{peer_ip}")
def peer_detail(peer_ip: str) -> dict[str, Any]:
    normalized_peer_ip = _validate_peer_ip(peer_ip)
    summary = _fetch_one(
        """
        select
          peer_ip::text as peer_ip,
          peer_asn,
          route_count,
          prefix_count,
          origin_asn_count,
          collector_count,
          updated_at
        from bgp_summary_current_by_peer
        where peer_ip = %s::inet
        limit 1;
        """,
        (normalized_peer_ip,),
    )
    observations: list[dict[str, Any]] = []
    if summary is None:
        summary = {}
    else:
        observations = [
            {
                "observed_peer_ip": summary.get("peer_ip"),
                "observed_peer_asn": summary.get("peer_asn"),
                "observed_routes": summary.get("route_count"),
                "observed_prefixes": summary.get("prefix_count"),
                "inventory_peer_name": None,
                "inventory_connection_type": None,
                "inventory_status": None,
                "router_hostname": None,
                "router_role": None,
                "interface_name": None,
                "interface_description": None,
                "ixp_name": None,
                "site_name": None,
                "match_status": "SUMMARY",
                "ping_status": None,
                "packets_sent": None,
                "packets_received": None,
                "packet_loss_percent": None,
                "rtt_min_ms": None,
                "rtt_avg_ms": None,
                "rtt_max_ms": None,
                "rtt_mdev_ms": None,
                "ping_measured_at": summary.get("updated_at"),
            }
        ]
    latest_ping = None
    ping_summary = None
    latest_traceroute = None
    latest_traceroute_hops: list[dict[str, Any]] = []
    latest_traceroute_hops_enriched: list[dict[str, Any]] = []
    latest_traceroute_hops_with_classification: list[dict[str, Any]] = []
    traceroute_hop_summary_for_peer = None
    traceroute_classification_summary_for_peer = None
    current_routes = _fetch_all(
        """
        select
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          next_hop::text as next_hop,
          as_path,
          origin_asn,
          origin_type,
          first_seen,
          last_seen,
          inventory_peer_name,
          inventory_connection_type,
          inventory_peer_status,
          router_hostname,
          router_role,
          interface_name,
          interface_description,
          ixp_name,
          site_name,
          enrichment_status,
          ping_status,
          packet_loss_percent,
          rtt_avg_ms,
          rtt_max_ms,
          ping_measured_at
        from v_bgp_current_routes_with_ping
        where peer_ip = %s::inet
        order by prefix::text, collector;
        """,
        (normalized_peer_ip,),
    )
    recent_changes = _fetch_all(
        """
        select
          detected_at,
          source,
          collector,
          peer_ip::text as peer_ip,
          peer_asn,
          prefix::text as prefix,
          change_type,
          old_as_path,
          new_as_path,
          old_next_hop::text as old_next_hop,
          new_next_hop::text as new_next_hop,
          old_origin_asn,
          new_origin_asn,
          inventory_peer_name,
          inventory_connection_type,
          ixp_name,
          router_hostname,
          enrichment_status,
          ping_status,
          packet_loss_percent,
          rtt_avg_ms,
          rtt_max_ms,
          ping_measured_at
        from v_bgp_route_changes_with_ping
        where peer_ip = %s::inet
        order by detected_at desc
        limit 50;
        """,
        (normalized_peer_ip,),
    )
    return {
        "peer_ip": normalized_peer_ip,
        "peer_summary": summary,
        "latest_ping": latest_ping,
        "ping_summary": ping_summary,
        "latest_traceroute": latest_traceroute,
        "latest_traceroute_hops": latest_traceroute_hops,
        "latest_traceroute_hops_enriched": latest_traceroute_hops_enriched,
        "latest_traceroute_hops_with_classification": latest_traceroute_hops_with_classification,
        "traceroute_hop_summary_for_peer": traceroute_hop_summary_for_peer,
        "traceroute_classification_summary_for_peer": traceroute_classification_summary_for_peer,
        "current_routes": current_routes,
        "recent_changes": recent_changes,
    }


@router.get("/synthetic/runs/latest")
def synthetic_latest_runs(limit: int = Query(10, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          run_id,
          url,
          final_url,
          title,
          analyzed_at,
          total_requests,
          total_hosts,
          total_ips_measured,
          ping_success,
          ping_failed,
          avg_rtt_avg_ms,
          max_rtt_avg_ms,
          traceroute_success,
          traceroute_failed,
          ips_with_bgp_match
        from v_synthetic_browser_latest_domain_report
        order by analyzed_at desc, run_id desc
        limit %s;
        """,
        (limit,),
    )


@router.get("/synthetic/runs/{run_id}")
def synthetic_run_detail(run_id: int) -> dict[str, Any]:
    summary = _fetch_one(
        """
        select
          run_id,
          url,
          final_url,
          title,
          label,
          analyzed_at,
          total_requests,
          total_hosts,
          total_ipv4,
          total_ipv6,
          total_ips_measured,
          measured_rows,
          ping_success,
          ping_failed,
          avg_rtt_avg_ms,
          min_rtt_avg_ms,
          max_rtt_avg_ms,
          traceroute_success,
          traceroute_failed,
          avg_traceroute_hop_count,
          ips_with_bgp_match,
          hosts_with_bgp_match,
          hosts_with_ping_failure,
          hosts_with_traceroute_failure
        from v_synthetic_browser_run_operational_summary
        where run_id = %s;
        """,
        (run_id,),
    )
    if summary is None:
        return {"summary": None, "hosts": [], "ip_results": []}

    hosts = _fetch_all(
        """
        select
          run_id,
          analyzed_at,
          url,
          final_url,
          hostname,
          request_count,
          dns_error,
          ipv4_count,
          ipv6_count,
          selected_ipv4_count,
          measured_ips,
          ping_success,
          ping_failed,
          avg_rtt_avg_ms,
          max_rtt_avg_ms,
          traceroute_success,
          traceroute_failed,
          avg_traceroute_hop_count,
          ips_with_bgp_match
        from v_synthetic_browser_run_host_detail
        where run_id = %s
        order by hostname;
        """,
        (run_id,),
    )
    ip_results = _fetch_all(
        """
        select
          run_id,
          analyzed_at,
          url,
          final_url,
          title,
          hostname,
          ip::text as ip,
          bgp_route_count,
          has_bgp_match,
          ping_status,
          packet_loss_percent,
          rtt_avg_ms,
          rtt_max_ms,
          traceroute_status,
          traceroute_hop_count,
          traceroute_responded_hop_count
        from v_synthetic_browser_run_ip_detail
        where run_id = %s
        order by hostname, ip;
        """,
        (run_id,),
    )
    return {"summary": summary, "hosts": hosts, "ip_results": ip_results}


@router.get("/synthetic/domain")
def synthetic_domain(url: str = Query(..., min_length=1)) -> dict[str, Any]:
    normalized_url = _normalize_url(url)
    domain_summary = _fetch_one(
        """
        select
          url,
          final_url,
          title,
          total_runs,
          last_run_id,
          first_analyzed_at,
          last_analyzed_at,
          total_hosts_observed,
          total_ips_measured,
          total_ping_success,
          total_ping_failed,
          avg_rtt_avg_ms,
          min_rtt_avg_ms,
          max_rtt_avg_ms,
          total_traceroutes_run,
          total_traceroute_success,
          avg_traceroute_hops,
          total_ips_with_bgp_match
        from v_synthetic_browser_domain_summary
        where url = %s or final_url = %s or coalesce(final_url, url) = %s
        limit 1;
        """,
        (normalized_url, normalized_url, normalized_url),
    )
    latest_run = _fetch_one(
        """
        select
          run_id,
          url,
          final_url,
          title,
          analyzed_at,
          total_requests,
          total_hosts,
          total_ips_measured,
          ping_success,
          ping_failed,
          avg_rtt_avg_ms,
          max_rtt_avg_ms,
          traceroute_success,
          traceroute_failed,
          ips_with_bgp_match
        from v_synthetic_browser_latest_domain_report
        where url = %s or final_url = %s or coalesce(final_url, url) = %s
        limit 1;
        """,
        (normalized_url, normalized_url, normalized_url),
    )
    latest_ip_results = (
        _fetch_all(
            """
            select
              run_id,
              analyzed_at,
              url,
              final_url,
              title,
              hostname,
              ip::text as ip,
              bgp_route_count,
              has_bgp_match,
              ping_status,
              packet_loss_percent,
              rtt_avg_ms,
              rtt_max_ms,
              traceroute_status,
              traceroute_hop_count,
              traceroute_responded_hop_count
            from v_synthetic_browser_run_ip_detail
            where run_id = %s
            order by hostname, ip;
            """,
            (latest_run["run_id"],),
        )
        if latest_run is not None
        else []
    )
    return {
        "domain_summary": domain_summary,
        "latest_run": latest_run,
        "latest_ip_results": latest_ip_results,
    }


@router.get("/synthetic/hosts/{hostname}")
def synthetic_host(hostname: str) -> dict[str, Any]:
    host_summary = _fetch_one(
        """
        select
          hostname,
          total_runs,
          total_ips_measured,
          avg_rtt_avg_ms,
          min_rtt_avg_ms,
          max_rtt_avg_ms,
          total_bgp_matches,
          last_seen
        from v_synthetic_browser_host_summary
        where lower(hostname) = lower(%s)
        limit 1;
        """,
        (hostname,),
    )
    latest_ip_results = []
    if host_summary is not None:
        latest_ip_results = _fetch_all(
            """
            with latest_run as (
                select run_id
                from v_synthetic_browser_run_ip_detail
                where lower(hostname) = lower(%s)
                order by analyzed_at desc, run_id desc
                limit 1
            )
            select
              run_id,
              analyzed_at,
              url,
              final_url,
              hostname,
              ip::text as ip,
              bgp_route_count,
              has_bgp_match,
              ping_status,
              packet_loss_percent,
              rtt_avg_ms,
              rtt_max_ms,
              traceroute_status,
              traceroute_hop_count,
              traceroute_responded_hop_count
            from v_synthetic_browser_run_ip_detail
            where lower(hostname) = lower(%s)
              and run_id = (select run_id from latest_run)
            order by ip;
            """,
            (hostname, hostname),
        )
    return {
        "host_summary": host_summary,
        "latest_ip_results": latest_ip_results,
    }


@router.get("/synthetic/ip-results")
def synthetic_ip_results(run_id: int = Query(..., ge=1), limit: int = Query(100, ge=1, le=1000)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          run_id,
          analyzed_at,
          url,
          final_url,
          title,
          hostname,
          ip::text as ip,
          bgp_route_count,
          has_bgp_match,
          ping_status,
          packet_loss_percent,
          rtt_avg_ms,
          rtt_max_ms,
          traceroute_status,
          traceroute_hop_count,
          traceroute_responded_hop_count
        from v_synthetic_browser_run_ip_detail
        where run_id = %s
        order by hostname, ip
        limit %s;
        """,
        (run_id, limit),
    )


@router.get("/inventory/peers/unmatched")
def unmatched_inventory_peers(limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
    return _call_operational_query(list_unmatched_bgp_peers, limit)


@router.get("/inventory/peers/matched")
def matched_inventory_peers(limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          observed_peer_ip::text as observed_peer_ip,
          observed_peer_asn,
          observed_routes,
          observed_prefixes,
          inventory_peer_name,
          inventory_connection_type,
          inventory_status,
          router_hostname,
          ixp_name,
          site_name,
          match_status
        from v_bgp_peer_inventory_match
        where match_status = 'MATCHED'
        order by observed_routes desc, observed_peer_ip
        limit %s;
        """,
        (limit,),
    )


@router.get("/inventory/sites")
def inventory_sites() -> list[dict[str, Any]]:
    return _call_operational_query(list_sites)


@router.get("/inventory/sites/{site_code}")
def inventory_site(site_code: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_operational_query(get_site, site_code)


@router.get("/inventory/sites/{site_code}/hosts")
def inventory_site_hosts(
    site_code: str = FastAPIPath(..., min_length=1),
    include_interfaces: bool = Query(True),
    include_peers: bool = Query(True),
) -> dict[str, Any]:
    return _call_operational_query(list_hosts_by_site, site_code, include_interfaces, include_peers)


@router.get("/inventory/sites/{site_code}/public-context")
def inventory_site_public_context(site_code: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_operational_query(get_inventory_public_context, site_code, "CE", 20)


@router.get("/inventory/hosts")
def inventory_hosts(
    site_code: str | None = Query(default=None),
    role: str | None = Query(default=None),
    tag: str | None = Query(default=None),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return _call_operational_query(list_hosts, site_code, role, tag, limit)


@router.get("/inventory/hosts/{hostname}")
def inventory_host(hostname: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_operational_query(get_host, hostname)


@router.get("/inventory/search")
def inventory_search(q: str = Query(..., min_length=1), limit: int = Query(50, ge=1, le=200)) -> list[dict[str, Any]]:
    return _call_operational_query(search_hosts, q, limit)


@router.get("/inventory/peer-links")
def inventory_peer_links(
    site_code: str | None = Query(default=None),
    peer_ip: str | None = Query(default=None),
    peer_asn: int | None = Query(default=None, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return _call_operational_query(list_peer_links, site_code, peer_ip, peer_asn, limit)


@router.get("/inventory/ui")
def inventory_ui() -> FileResponse:
    html_path = _STATIC_DIR / "inventory.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return FileResponse(html_path)


@router.get("/external-routes/ui")
def external_routes_ui() -> FileResponse:
    html_path = _STATIC_DIR / "external_routes.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return FileResponse(html_path)


@router.get("/route-graph/ui")
def route_graph_ui() -> FileResponse:
    html_path = _STATIC_DIR / "route_graph.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return FileResponse(html_path)


@router.get("/route-memory/graph-viewer")
def route_memory_graph_viewer() -> FileResponse:
    html_path = _STATIC_DIR / "route_memory_graph_viewer.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return FileResponse(html_path)


@router.head("/route-memory/graph-viewer")
def route_memory_graph_viewer_head() -> Response:
    html_path = _STATIC_DIR / "route_memory_graph_viewer.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return Response(status_code=200, media_type="text/html")


@router.get("/route-graph/workspace")
def route_graph_workspace() -> FileResponse:
    html_path = _STATIC_DIR / "route_graph_workspace.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return FileResponse(html_path)


@router.get("/route-memory/graphs/latest")
def route_memory_graph_latest() -> dict[str, Any]:
    snapshot = fetch_latest_route_memory_graph_snapshot()
    if snapshot is None:
        return {"status": "empty", "message": "No route memory graph snapshots found"}
    return snapshot


@router.head("/route-memory/graphs/latest")
def route_memory_graph_latest_head() -> Response:
    return Response(status_code=200, media_type="application/json")


@router.get("/route-memory/graphs/{graph_uid}")
def route_memory_graph_by_uid(graph_uid: str) -> dict[str, Any]:
    snapshot = fetch_route_memory_graph_snapshot(graph_uid)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Route memory graph snapshot not found.")
    return snapshot


@router.head("/route-memory/graphs/{graph_uid}")
def route_memory_graph_by_uid_head(graph_uid: str) -> Response:
    return Response(status_code=200, media_type="application/json")


def _grafana_empty_response() -> dict[str, Any]:
    return {"status": "empty", "message": "No route memory graph snapshots found"}


def _grafana_not_found_response(graph_uid: str) -> dict[str, Any]:
    return {
        "status": "not_found",
        "message": "Route memory graph snapshot not found",
        "graph_uid": graph_uid,
    }


def _grafana_snapshot_response(snapshot) -> dict[str, Any]:
    return {
        "status": "ok",
        "graph_uid": snapshot.graph_uid,
        "data": {
            "summary": build_grafana_summary(snapshot),
            "nodes": build_grafana_node_rows(snapshot),
            "edges": build_grafana_edge_rows(snapshot),
            "divergences": build_grafana_divergence_rows(snapshot),
        },
    }


def _grafana_payload_or_empty(snapshot, *, section: str | None = None) -> dict[str, Any]:
    if snapshot is None:
        return _grafana_empty_response()
    data = _grafana_snapshot_response(snapshot)
    if section is None:
        return data
    return {
        "status": "ok",
        "graph_uid": snapshot.graph_uid,
        "count": len(data["data"][section]),
        "data": data["data"][section],
    }


@router.get("/route-memory/grafana/latest")
def route_memory_grafana_latest() -> dict[str, Any]:
    snapshot = None
    with get_connection() as conn:
        try:
            snapshot = load_latest_graph_snapshot(conn)
        except LookupError:
            return _grafana_empty_response()
    return _grafana_snapshot_response(snapshot)


@router.get("/route-memory/grafana/latest/summary")
def route_memory_grafana_latest_summary() -> dict[str, Any]:
    snapshot = None
    with get_connection() as conn:
        try:
            snapshot = load_latest_graph_snapshot(conn)
        except LookupError:
            return _grafana_empty_response()
    summary = build_grafana_summary(snapshot)
    return {"status": "ok", "graph_uid": snapshot.graph_uid, "data": summary}


@router.get("/route-memory/grafana/latest/nodes")
def route_memory_grafana_latest_nodes() -> dict[str, Any]:
    snapshot = None
    with get_connection() as conn:
        try:
            snapshot = load_latest_graph_snapshot(conn)
        except LookupError:
            return _grafana_empty_response()
    nodes = build_grafana_node_rows(snapshot)
    return {"status": "ok", "graph_uid": snapshot.graph_uid, "count": len(nodes), "data": nodes}


@router.get("/route-memory/grafana/latest/edges")
def route_memory_grafana_latest_edges() -> dict[str, Any]:
    snapshot = None
    with get_connection() as conn:
        try:
            snapshot = load_latest_graph_snapshot(conn)
        except LookupError:
            return _grafana_empty_response()
    edges = build_grafana_edge_rows(snapshot)
    return {"status": "ok", "graph_uid": snapshot.graph_uid, "count": len(edges), "data": edges}


@router.get("/route-memory/grafana/latest/divergences")
def route_memory_grafana_latest_divergences() -> dict[str, Any]:
    snapshot = None
    with get_connection() as conn:
        try:
            snapshot = load_latest_graph_snapshot(conn)
        except LookupError:
            return _grafana_empty_response()
    divergences = build_grafana_divergence_rows(snapshot)
    return {"status": "ok", "graph_uid": snapshot.graph_uid, "count": len(divergences), "data": divergences}


@router.get("/route-memory/grafana/graphs/{graph_uid}")
def route_memory_grafana_graph(graph_uid: str) -> dict[str, Any]:
    with get_connection() as conn:
        try:
            snapshot = load_graph_snapshot_by_uid(conn, graph_uid)
        except LookupError:
            return _grafana_not_found_response(graph_uid)
    return _grafana_snapshot_response(snapshot)


@router.get("/route-memory/grafana/graphs/{graph_uid}/summary")
def route_memory_grafana_graph_summary(graph_uid: str) -> dict[str, Any]:
    with get_connection() as conn:
        try:
            snapshot = load_graph_snapshot_by_uid(conn, graph_uid)
        except LookupError:
            return _grafana_not_found_response(graph_uid)
    return {"status": "ok", "graph_uid": snapshot.graph_uid, "data": build_grafana_summary(snapshot)}


@router.get("/route-memory/grafana/graphs/{graph_uid}/nodes")
def route_memory_grafana_graph_nodes(graph_uid: str) -> dict[str, Any]:
    with get_connection() as conn:
        try:
            snapshot = load_graph_snapshot_by_uid(conn, graph_uid)
        except LookupError:
            return _grafana_not_found_response(graph_uid)
    nodes = build_grafana_node_rows(snapshot)
    return {"status": "ok", "graph_uid": snapshot.graph_uid, "count": len(nodes), "data": nodes}


@router.get("/route-memory/grafana/graphs/{graph_uid}/edges")
def route_memory_grafana_graph_edges(graph_uid: str) -> dict[str, Any]:
    with get_connection() as conn:
        try:
            snapshot = load_graph_snapshot_by_uid(conn, graph_uid)
        except LookupError:
            return _grafana_not_found_response(graph_uid)
    edges = build_grafana_edge_rows(snapshot)
    return {"status": "ok", "graph_uid": snapshot.graph_uid, "count": len(edges), "data": edges}


@router.get("/route-memory/grafana/graphs/{graph_uid}/divergences")
def route_memory_grafana_graph_divergences(graph_uid: str) -> dict[str, Any]:
    with get_connection() as conn:
        try:
            snapshot = load_graph_snapshot_by_uid(conn, graph_uid)
        except LookupError:
            return _grafana_not_found_response(graph_uid)
    divergences = build_grafana_divergence_rows(snapshot)
    return {"status": "ok", "graph_uid": snapshot.graph_uid, "count": len(divergences), "data": divergences}


@router.get("/route-learning/demo/ui")
def route_learning_demo_ui() -> FileResponse:
    html_path = _STATIC_DIR / "route_learning_demo.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return FileResponse(html_path)


@router.get("/route-learning/demo/8.8.8.8/visual")
def route_learning_demo_visual() -> dict[str, Any]:
    try:
        return get_route_learning_demo_payload()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/route-learning/sessions/demo/8.8.8.8/visual")
def route_learning_session_demo_visual() -> dict[str, Any]:
    try:
        return build_route_learning_visual_payload("8.8.8.8", service="google")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/route-learning/sessions/demo/cloudflare/visual")
def route_learning_session_demo_cloudflare_visual() -> dict[str, Any]:
    try:
        return build_route_learning_visual_payload("cloudflare", service="cloudflare")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/route-learning/sessions/demo/cloudflare/dedicated-run-plan")
def route_learning_session_demo_cloudflare_dedicated_run_plan() -> dict[str, Any]:
    try:
        payload = build_route_learning_visual_payload("cloudflare", service="cloudflare")
        plan = payload.get("dedicated_run_plan")
        if not isinstance(plan, dict):
            raise ValueError("Plano dedicado da Cloudflare não encontrado.")
        return plan
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/route-learning/sessions/demo/cloudflare/post-change-run-plan")
def route_learning_session_demo_cloudflare_post_change_run_plan() -> dict[str, Any]:
    try:
        return build_cloudflare_post_change_run_plans()
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/route-learning/sessions/demo/cloudflare/learning-comparison-plan")
def route_learning_session_demo_cloudflare_learning_comparison_plan() -> dict[str, Any]:
    try:
        return build_learning_comparison_plan("cloudflare", target="cloudflare")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/route-learning/sessions/demo/cloudflare/route-profile")
def route_learning_session_demo_cloudflare_route_profile() -> dict[str, Any]:
    try:
        return build_route_profile("cloudflare", target="1.1.1.1")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/route-learning/sessions/demo/cloudflare/temporal-comparison")
def route_learning_session_demo_cloudflare_temporal_comparison() -> dict[str, Any]:
    try:
        return build_temporal_profile_comparison("cloudflare", target="1.1.1.1")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/route-learning/sessions/demo/cloudflare/dedicated-run")
def route_learning_session_demo_cloudflare_dedicated_run(
    payload: RouteLearningCloudflareDedicatedRunRequest | None = None,
    *,
    request: Request,
) -> dict[str, Any]:
    payload = payload or RouteLearningCloudflareDedicatedRunRequest(plan_uid="plan-cloudflare-dedicated-trace-v1", target="1.1.1.1")
    current_user = get_current_user(request)
    if current_user is None:
        raise HTTPException(status_code=401, detail="Não autenticado.")
    if not is_admin(current_user):
        raise HTTPException(status_code=403, detail="Ação exige permissão de operador/admin.")
    try:
        result = run_cloudflare_dedicated_trace(
            confirm=payload.confirm,
            plan_uid=payload.plan_uid,
            target=payload.target,
            requested_by_role=current_user.role,
            requested_by_username=current_user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    response = {
        "status": result.get("status"),
        "plan_uid": result.get("plan_uid"),
        "target": result.get("target"),
        "service": result.get("service"),
        "active_action_executed": result.get("active_action_executed", False),
        "dedicated_run_uid": result.get("dedicated_run_uid"),
        "ping_summary": result.get("ping_summary") or {},
        "traceroute_summary": result.get("traceroute_summary") or {},
        "persisted": result.get("persisted", False),
        "route_learning_visual_endpoint": result.get("route_learning_visual_endpoint"),
        "comparison_endpoint": result.get("comparison_endpoint"),
        "operator_message": result.get("operator_message"),
        "limitations": result.get("limitations") or [],
    }
    return response


@router.get("/external-routes/services")
def external_routes_services() -> list[dict[str, Any]]:
    return list_external_services()


@router.get("/external-routes/services/{service}/summary")
def external_routes_service_summary(service: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return get_service_route_summary(service)


@router.get("/external-routes/services/{service}/hops")
def external_routes_service_hops(
    service: str = FastAPIPath(..., min_length=1),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return list_external_hops(service=service, limit=limit)


@router.get("/external-routes/services/{service}/edges")
def external_routes_service_edges(
    service: str = FastAPIPath(..., min_length=1),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return list_external_route_edges(service, limit=limit)


@router.get("/external-routes/hops")
def external_routes_hops(
    service: str | None = Query(default=None),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return list_external_hops(service=service, limit=limit)


@router.get("/external-routes/hops/{ip:path}/context")
def external_routes_hop_context(ip: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    try:
        return get_external_hop_context(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/external-routes/hops/{ip:path}")
def external_routes_hop(ip: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    try:
        hop = get_external_hop(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="IP inválido.") from exc
    if hop is None:
        raise HTTPException(status_code=404, detail="Hop não encontrado.")
    return hop


@router.get("/external-routes/services/{service}/trace-runs/{run_uid}/graph")
def external_routes_service_trace_graph(
    service: str = FastAPIPath(..., min_length=1),
    run_uid: str = FastAPIPath(..., min_length=1),
) -> dict[str, Any]:
    graph = get_external_route_trace_graph(run_uid)
    if not graph.get("available"):
        return graph
    if graph.get("service_uid") and str(graph.get("service_uid")) != str(service).strip().lower():
        raise HTTPException(status_code=404, detail="Graph não encontrado para o serviço informado.")
    return graph


@router.get("/external-routes/unknown-hops")
def external_routes_unknown_hops(limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
    return list_external_hops(limit=limit, unknown_only=True)


@router.get("/external-routes/compare")
def external_routes_compare(
    service_a: str = Query(..., min_length=1),
    service_b: str = Query(..., min_length=1),
) -> dict[str, Any]:
    return compare_service_routes(service_a, service_b)


@router.get("/route-graph/global")
def route_graph_global() -> dict[str, Any]:
    return build_global_route_graph()


@router.get("/route-graph/service/{service}")
def route_graph_service(service: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    try:
        return build_service_route_graph(service)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/route-graph/hop/{ip:path}")
def route_graph_hop(ip: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    try:
        return get_route_graph_hop_context(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/route-graph/compare")
def route_graph_compare(
    service_a: str = Query(..., min_length=1),
    service_b: str = Query(..., min_length=1),
) -> dict[str, Any]:
    try:
        return compare_route_graph_services(service_a, service_b)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/route-graph/clusters")
def route_graph_clusters() -> dict[str, Any]:
    return list_route_graph_clusters()


@router.get("/route-graph/unknown")
def route_graph_unknown() -> dict[str, Any]:
    return list_unknown_route_graph_hops()


@router.get("/route-graph/private-path")
def route_graph_private_path() -> dict[str, Any]:
    return build_private_path_graph()


@router.post("/external-routes/seed-services")
def external_routes_seed_services() -> dict[str, Any]:
    seeded = seed_external_services()
    return seeded


@router.post("/external-routes/ingest-existing")
def external_routes_ingest_existing(payload: ExternalRoutesIngestRequest | None = None) -> dict[str, Any]:
    payload = payload or ExternalRoutesIngestRequest()
    return ingest_existing_traceroutes(dry_run=payload.dry_run)


@router.post("/external-routes/enrich")
def external_routes_enrich(payload: ExternalRoutesEnrichRequest | None = None) -> dict[str, Any]:
    payload = payload or ExternalRoutesEnrichRequest()
    limit = max(1, min(int(payload.limit), 500))
    hops = list_external_hops(limit=limit, unknown_only=True)
    enriched: list[dict[str, Any]] = []
    for hop in hops:
        hop_ip = hop.get("hop_ip")
        if not hop_ip:
            continue
        enriched.append(enrich_external_hop(str(hop_ip)))
    summary = rebuild_service_hop_summary()
    return {
        "status": "ok",
        "enriched": enriched,
        "count": len(enriched),
        "summary": summary,
    }


@router.post("/external-routes/services/{service}/trace")
def external_routes_service_trace(
    service: str = FastAPIPath(..., min_length=1),
    payload: ExternalRoutesTraceRequest | None = None,
    *,
    request: Request,
) -> dict[str, Any]:
    payload = payload or ExternalRoutesTraceRequest()
    current_user = get_current_user(request)
    if current_user is None or not is_admin(current_user):
        raise HTTPException(status_code=403, detail="Ação exige permissão de operador/admin.")
    if not payload.confirm:
        raise HTTPException(status_code=400, detail='Confirmação explícita obrigatória: envie {"confirm": true}.')
    max_hops = max(1, min(int(payload.max_hops or 20), 20))
    try:
        return run_external_route_service_trace(
            service,
            confirm=True,
            target_override=payload.target_override,
            max_hops=max_hops,
            requested_by_role=current_user.role,
            requested_by_username=current_user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/inventory/discovery/runs")
def inventory_discovery_runs(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    return {"items": _call_operational_query(list_discovery_runs, limit)}


@router.get("/inventory/discovery/candidates")
def inventory_discovery_candidates(
    status: str | None = Query(default=None),
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    return {
        "summary": _call_operational_query(discovery_summary),
        "items": _call_operational_query(list_host_candidates, status, limit),
    }


@router.get("/inventory/discovery/candidates/{candidate_uid}")
def inventory_discovery_candidate(candidate_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_operational_query(get_host_candidate, candidate_uid)


@router.post("/inventory/discovery/collect")
def inventory_discovery_collect(payload: InventoryDiscoveryCollectRequest) -> dict[str, Any]:
    if payload.source != "mikrotik":
        raise HTTPException(status_code=400, detail="Fonte de descoberta não suportada.")
    return _call_operational_query(collect_mikrotik_host_inventory, payload.limit, payload.dry_run)


@router.post("/inventory/discovery/candidates/{candidate_uid}/promote")
def inventory_discovery_candidate_promote(
    payload: InventoryCandidatePromoteRequest,
    request: Request,
    candidate_uid: str = FastAPIPath(..., min_length=1),
) -> dict[str, Any]:
    auth = auth_payload_for_request(request)
    return _call_operational_query(
        promote_candidate_to_inventory,
        candidate_uid,
        payload.site_code,
        payload.confirm,
        auth.get("username"),
    )


@router.post("/inventory/discovery/candidates/{candidate_uid}/ignore")
def inventory_discovery_candidate_ignore(
    payload: InventoryCandidateIgnoreRequest,
    candidate_uid: str = FastAPIPath(..., min_length=1),
) -> dict[str, Any]:
    return _call_operational_query(ignore_candidate, candidate_uid, payload.reason, payload.confirm)


@router.get("/ixbr/locations")
def ixbr_locations() -> list[dict[str, Any]]:
    return _call_operational_query(list_ixbr_locations)


@router.get("/ixbr/locations/{locality_code}/participants")
def ixbr_location_participants(
    locality_code: str = FastAPIPath(..., min_length=1),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return _call_operational_query(list_ixbr_participants, locality_code, limit)


@router.get("/ixbr/locations/{locality_code}/bgp-summary")
def ixbr_location_bgp_summary(locality_code: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_operational_query(summarize_ixbr_vs_bgp, locality_code)


@router.get("/ixbr/locations/{locality_code}/participants/seen-as-origin")
def ixbr_location_participants_seen_as_origin(
    locality_code: str = FastAPIPath(..., min_length=1),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return _call_operational_query(list_ixbr_asns_seen_as_origin, locality_code, limit)


@router.get("/ixbr/locations/{locality_code}/participants/not-seen-as-origin")
def ixbr_location_participants_not_seen_as_origin(
    locality_code: str = FastAPIPath(..., min_length=1),
    limit: int = Query(100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return _call_operational_query(list_ixbr_participants_without_bgp_origin, locality_code, limit)


@router.get("/ixbr/locations/{locality_code}/participants/{asn}")
def ixbr_location_participant(
    locality_code: str = FastAPIPath(..., min_length=1),
    asn: int = FastAPIPath(..., ge=0),
) -> dict[str, Any]:
    return _call_operational_query(get_ixbr_participant, locality_code, asn)


@router.post("/questions/ask")
def question_ask(payload: QuestionAskRequest) -> dict[str, Any]:
    try:
        if is_public_review_mode() and payload.compact is False:
            raise HTTPException(status_code=403, detail=PUBLIC_REVIEW_BLOCKED_MESSAGE)
        if payload.compact is False:
            created = _call_learning_query(
                create_learning_request,
                payload.question,
                operator=payload.operator,
                raw_context={"source": "questions_api", "dry_run": True},
            )
            request_uid = (created.get("request") or {}).get("request_uid")
            if request_uid:
                response = {
                    "compact": False,
                    "request_uid": request_uid,
                    "links": {
                        "detail": f"/learning/requests/{request_uid}",
                        "answer": f"/learning/requests/{request_uid}/answer",
                        "compact": f"/questions/{request_uid}",
                    },
                    "detail": created,
                }
                return sanitize_public_payload(response) if is_public_review_mode() else response
            return sanitize_public_payload(created) if is_public_review_mode() else created
        response = _call_question_query(ask_question_compact, payload.question, operator=payload.operator)
        return sanitize_public_payload(response) if is_public_review_mode() else response
    except HTTPException:
        raise
    except ValueError as exc:
        return _question_error_payload(
            "invalid_question_flow",
            "A pergunta não pôde ser processada.",
            str(exc),
        )
    except RuntimeError as exc:
        return _question_error_payload(
            "question_flow_failed",
            "A pergunta encontrou um erro operacional recuperável.",
            str(exc),
        )
    except Exception as exc:
        return _question_error_payload(
            "question_flow_unexpected_error",
            "A pergunta encontrou um erro inesperado.",
            "Falha interna registrada; revise os logs do serviço.",
        )


@router.get("/questions/recent")
def questions_recent(limit: int = Query(20, ge=1, le=100)) -> list[dict[str, Any]]:
    response = _call_question_query(list_recent_questions_compact, limit=limit)
    return sanitize_public_payload(response) if is_public_review_mode() else response


@router.get("/questions/ui")
def questions_ui() -> FileResponse:
    html_path = _STATIC_DIR / "questions.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return FileResponse(html_path)


@router.post("/questions/{request_uid}/speech", response_model=QuestionSpeechResponse)
def question_speech(
    request_uid: str = FastAPIPath(..., min_length=1),
    payload: QuestionSpeechRequest | None = None,
) -> dict[str, Any]:
    payload = payload or QuestionSpeechRequest()
    question = _call_question_query(get_question_compact, request_uid)
    if question is None:
        _raise_not_found("Pergunta não encontrada.")
    text_mode = payload.text_mode if payload.text_mode in {"answer", "full"} else "answer"
    speech_text, truncated = build_speech_text_from_question_response(question, mode=text_mode)
    if not speech_text:
        return {
            "request_uid": request_uid,
            "status": "error",
            "tts_enabled": is_tts_enabled(),
            "provider": payload.provider or get_tts_config()["default_provider"],
            "language": payload.language or get_tts_config()["language"],
            "voice": payload.voice or get_tts_config()["voice"],
            "audio_url": None,
            "audio_mime_type": None,
            "text_length": 0,
            "message": "Não há texto suficiente para gerar áudio.",
            "truncated": False,
        }
    result = generate_question_audio(
        speech_text,
        provider=payload.provider,
        voice=payload.voice,
        language=payload.language,
    )
    status = result.get("status") or "error"
    filename = extract_audio_filename(result.get("audio_url"), result.get("filename"))
    proxy_audio_url = f"/tts/audio/{filename}" if filename else None
    return {
        "request_uid": request_uid,
        "status": status,
        "tts_enabled": is_tts_enabled(),
        "provider": result.get("provider") or payload.provider or get_tts_config()["default_provider"],
        "language": payload.language or get_tts_config()["language"],
        "voice": payload.voice or get_tts_config()["voice"],
        "audio_url": proxy_audio_url,
        "audio_mime_type": result.get("mime_type"),
        "audio_source_url": result.get("audio_url"),
        "filename": filename,
        "text_length": len(speech_text),
        "message": result.get("message"),
        "truncated": truncated,
    }


@router.get("/questions/tts-health")
def questions_tts_health() -> dict[str, Any]:
    return get_tts_health()


@router.get("/tts/health")
def tts_health() -> dict[str, Any]:
    return get_tts_health()


@router.api_route("/tts/audio/{filename}", methods=["GET", "HEAD"])
def tts_audio(filename: str = FastAPIPath(..., min_length=1)) -> Response:
    config = get_tts_config()
    if not config["enabled"]:
        raise HTTPException(status_code=503, detail="TTS desabilitado.")
    safe_filename = _validate_audio_filename(filename)
    upstream_url = f"{config['base_url'].rstrip('/')}/generated/{safe_filename}"
    try:
        upstream = requests.get(upstream_url, timeout=min(config["timeout_seconds"], 30), stream=True)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="TTS indisponível no momento.") from exc
    if upstream.status_code == 404:
        raise HTTPException(status_code=404, detail="Áudio não encontrado.")
    if not upstream.ok:
        raise HTTPException(status_code=502, detail="Falha ao recuperar áudio do TTS.")
    content_type = upstream.headers.get("content-type") or mimetypes.guess_type(safe_filename)[0] or "application/octet-stream"
    content = b"" if upstream.request.method == "HEAD" else upstream.content
    return Response(content=content, media_type=content_type, headers={"Cache-Control": "no-store"})


@router.get("/questions/{request_uid}")
def question_detail(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    response = _call_question_query(get_question_compact, request_uid)
    return sanitize_public_payload(response) if is_public_review_mode() else response


@router.get("/questions/{request_uid}/action-plan")
def question_action_plan(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    response = _call_question_query(get_question_action_plan, request_uid)
    if response is None:
        _raise_not_found("Pergunta não encontrada.")
    return sanitize_public_payload(response) if is_public_review_mode() else response


@router.get("/questions/{request_uid}/full")
def question_full(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    response = _call_learning_query(get_learning_request, request_uid)
    return sanitize_public_payload(response) if is_public_review_mode() else response


@router.get("/questions/{request_uid}/active-plan")
def question_active_plan(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    response = _call_question_query(get_question_active_plan, request_uid)
    return sanitize_public_payload(response) if is_public_review_mode() else response


@router.post("/questions/{request_uid}/approve-active")
def question_approve_active(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_question_query(approve_question_active, request_uid)


@router.post("/questions/{request_uid}/execute-active")
def question_execute_active(
    request_uid: str = FastAPIPath(..., min_length=1),
    payload: QuestionExecuteActiveRequest | None = None,
) -> dict[str, Any]:
    payload = payload or QuestionExecuteActiveRequest()
    return _call_question_query(execute_question_active, request_uid, confirm=payload.confirm)


@router.post("/questions/{request_uid}/actions/{action_id}")
def question_action_execute(
    request_uid: str = FastAPIPath(..., min_length=1),
    action_id: str = FastAPIPath(..., min_length=1),
    payload: QuestionActionRequest | None = None,
) -> dict[str, Any]:
    payload = payload or QuestionActionRequest()
    return _call_question_query(
        execute_question_action,
        request_uid,
        action_id,
        confirm=payload.confirm,
        target_override=payload.target_override,
        asn=payload.asn,
        label=payload.label,
        max_duration_seconds=payload.max_duration_seconds,
    )


@router.get("/questions/{request_uid}/traceroute-graph")
def question_traceroute_graph(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    graph = _call_question_query(get_traceroute_graph_for_learning_request, request_uid)
    if not graph.get("available"):
        return graph
    return graph


@router.get("/traceroute/runs/{run_id}/graph")
def traceroute_run_graph(run_id: int = FastAPIPath(..., ge=1)) -> dict[str, Any]:
    return _call_question_query(get_traceroute_graph_by_run, run_id)


@router.post("/learning/requests")
def learning_request_create(payload: LearningRequestCreate) -> dict[str, Any]:
    return _call_learning_query(
        create_learning_request,
        payload.question,
        operator=payload.operator,
        raw_context={"dry_run": payload.dry_run},
    )


@router.get("/learning/requests")
def learning_requests(
    status: str | None = Query(default=None),
    limit: int = Query(50, ge=1, le=500),
) -> list[dict[str, Any]]:
    return _call_learning_query(list_learning_requests, status=status, limit=limit)


@router.get("/learning/requests/{request_uid}")
def learning_request(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_learning_query(get_learning_request, request_uid)


@router.post("/learning/requests/{request_uid}/approve")
def learning_request_approve(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_learning_query(approve_learning_request, request_uid)


@router.post("/learning/requests/{request_uid}/execute")
def learning_request_execute(
    request_uid: str = FastAPIPath(..., min_length=1),
    payload: LearningRequestExecute | None = None,
) -> dict[str, Any]:
    payload = payload or LearningRequestExecute()
    return _call_learning_query(
        execute_learning_request,
        request_uid,
        dry_run=payload.dry_run,
        allow_safe_tasks=payload.allow_safe_tasks,
        allow_active_measurements=payload.allow_active_measurements,
        force_refresh=payload.force_refresh,
    )


@router.get("/learning/requests/{request_uid}/answer")
def learning_request_answer(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_learning_query(build_answer, request_uid)


@router.get("/learning/requests/{request_uid}/classifications")
def learning_request_classifications(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_learning_query(get_request_classifications, request_uid)


@router.post("/learning/requests/{request_uid}/classify")
def learning_request_classify(request_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_learning_query(classify_learning_request, request_uid, persist=True)


@router.get("/learning/memory/domain/{domain}")
def learning_memory_domain(domain: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return get_learning_memory_for_domain(domain)


@router.get("/learning/memory/entity")
def learning_memory_entity(
    type: str = Query(..., min_length=1),
    value: str = Query(..., min_length=1),
) -> dict[str, Any]:
    return summarize_learning_memory({"entity_type": type, "entity_value": value})


@router.get("/learning/classifications/entity")
def learning_classifications_entity(
    type: str = Query(..., min_length=1),
    value: str = Query(..., min_length=1),
) -> dict[str, Any]:
    return _call_learning_query(get_classifications_for_entity, type, value)


@router.get("/learning/known-networks")
def learning_known_networks() -> list[dict[str, Any]]:
    return _call_learning_query(list_known_networks)


@router.post("/semantic/rebuild")
def semantic_rebuild(payload: SemanticRebuildRequest | None = None) -> dict[str, Any]:
    payload = payload or SemanticRebuildRequest()
    return _call_operational_query(
        rebuild_semantic_documents,
        payload.scope,
        limit=payload.limit,
        dry_run=payload.dry_run,
        skip_existing=payload.skip_existing,
        force=payload.force,
    )


@router.get("/semantic/search")
def semantic_search_endpoint(
    q: str = Query(..., min_length=1),
    limit: int = Query(10, ge=1, le=500),
    object_type: str | None = Query(default=None, min_length=1),
) -> dict[str, Any]:
    return _call_operational_query(semantic_search, q, limit=limit, object_type=object_type)


@router.get("/semantic/metrics")
def semantic_metrics_endpoint() -> dict[str, Any]:
    from app.services.embedding_provider import get_embedding_provider_metrics

    return _call_operational_query(get_embedding_provider_metrics)


@router.get("/semantic/health")
def semantic_health_endpoint() -> dict[str, Any]:
    return _call_operational_query(semantic_healthcheck)


@router.get("/semantic/documents")
def semantic_documents(
    limit: int = Query(50, ge=1, le=500),
    object_type: str | None = Query(default=None, min_length=1),
) -> list[dict[str, Any]]:
    return _call_operational_query(list_semantic_documents, limit=limit, object_type=object_type)


@router.get("/semantic/documents/{document_uid}")
def semantic_document(document_uid: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    return _call_operational_query(get_semantic_document, document_uid)


@router.get("/learning/search")
def learning_search_endpoint(
    q: str = Query(..., min_length=1),
    limit: int = Query(10, ge=1, le=500),
) -> dict[str, Any]:
    return _call_operational_query(learning_search, q, limit=limit)


@router.get("/enrichment/asn/{asn}")
def enrichment_asn(
    asn: int = FastAPIPath(..., ge=1),
    refresh: bool = Query(False),
) -> dict[str, Any]:
    view = _compose_asn_enrichment_view(asn, refresh=refresh)
    if view is None:
        _raise_not_found("Nenhum enriquecimento de ASN disponível em cache.")
    return view


@router.get("/enrichment/ip")
def enrichment_ip(
    ip: str = Query(..., min_length=1),
    refresh: bool = Query(False),
) -> dict[str, Any]:
    view = _compose_ip_enrichment_view(ip, refresh=refresh)
    if view is None:
        _raise_not_found("Nenhum enriquecimento de IP disponível em cache.")
    return view


@router.post("/learning/requests/{request_uid}/enrich")
def learning_request_enrich(
    request_uid: str = FastAPIPath(..., min_length=1),
    payload: LearningRequestEnrich | None = None,
) -> dict[str, Any]:
    payload = payload or LearningRequestEnrich()
    return _call_learning_query(
        enrich_learning_request,
        request_uid,
        force_refresh=payload.force_refresh,
        allow_external=payload.allow_external,
    )


@router.get("/search/prefix")
def search_prefix(q: str = Query(..., min_length=1), limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          prefix::text as prefix,
          peer_ip::text as peer_ip,
          peer_asn,
          as_path,
          origin_asn,
          inventory_peer_name,
          inventory_connection_type,
          ixp_name,
          enrichment_status
        from v_bgp_current_routes_enriched
        where prefix::text like %s
        order by prefix::text, peer_ip::text
        limit %s;
        """,
        (f"{q}%", limit),
    )


@router.get("/measurements/ping/latest")
def ping_latest(limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
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
        order by measured_at desc, target::text
        limit %s;
        """,
        (limit,),
    )


@router.get("/measurements/ping/summary")
def ping_summary() -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          target::text as target,
          total_measurements,
          successful_measurements,
          failed_measurements,
          avg_packet_loss_percent,
          avg_rtt_avg_ms,
          min_rtt_avg_ms,
          max_rtt_avg_ms,
          first_measured_at,
          last_measured_at
        from v_active_ping_summary_by_target
        order by total_measurements desc, target;
        """
    )


@router.get("/measurements/ping/history/{target}")
def ping_history(target: str, limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    normalized_target = _validate_peer_ip(target)
    return _fetch_all(
        """
        select
          id,
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
        from active_ping_measurements
        where target = %s::inet
        order by measured_at desc, id desc
        limit %s;
        """,
        (normalized_target, limit),
    )


@router.get("/measurements/traceroute/latest")
def traceroute_latest(limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
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
        order by measured_at desc, target::text
        limit %s;
        """,
        (limit,),
    )


@router.get("/measurements/traceroute/summary")
def traceroute_summary() -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          target::text as target,
          total_measurements,
          successful_measurements,
          failed_measurements,
          avg_hop_count,
          avg_responded_hop_count,
          first_measured_at,
          last_measured_at
        from v_active_traceroute_summary_by_target
        order by total_measurements desc, target;
        """
    )


@router.get("/measurements/traceroute/history/{target}")
def traceroute_history(target: str, limit: int = Query(20, ge=1, le=500)) -> list[dict[str, Any]]:
    normalized_target = _validate_peer_ip(target)
    return _fetch_all(
        """
        select
          id,
          target::text as target,
          target_label,
          source_label,
          mode,
          max_hops,
          timeout_seconds,
          probes,
          returncode,
          status,
          hop_count,
          responded_hop_count,
          measured_at
        from active_traceroute_measurements
        where target = %s::inet
        order by measured_at desc, id desc
        limit %s;
        """,
        (normalized_target, limit),
    )


@router.get("/measurements/traceroute/hops/{measurement_id}")
def traceroute_hops(measurement_id: int) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          id,
          measurement_id,
          target::text as target,
          hop_number,
          hop_ip::text as hop_ip,
          responded,
          rtt_ms_values,
          rtt_avg_ms,
          raw_line
        from active_traceroute_hops
        where measurement_id = %s
        order by hop_number, id;
        """,
        (measurement_id,),
    )


@router.get("/measurements/traceroute/hop-summary")
def traceroute_hop_summary() -> dict[str, Any]:
    return _fetch_one("select * from v_active_traceroute_hop_summary;") or {}


@router.get("/measurements/traceroute/classification-summary")
def traceroute_classification_summary() -> dict[str, Any]:
    return _fetch_one("select * from v_active_traceroute_classification_summary;") or {}


@router.get("/measurements/traceroute/latest-hops-enriched/{target}")
def traceroute_latest_hops_enriched(target: str) -> list[dict[str, Any]]:
    normalized_target = _validate_peer_ip(target)
    return _fetch_all(
        """
        select
          measurement_id,
          target::text as target,
          target_label,
          measured_at,
          hop_number,
          hop_ip::text as hop_ip,
          responded,
          rtt_avg_ms,
          raw_line,
          ip_scope,
          is_private,
          is_public,
          inventory_match_status,
          router_hostname,
          router_role,
          router_management_ip::text as router_management_ip,
          interface_name,
          interface_description,
          interface_type,
          site_name,
          site_city
        from v_active_traceroute_latest_hops_enriched
        where target = %s::inet
        order by hop_number, measurement_id;
        """,
        (normalized_target,),
    )


@router.get("/measurements/traceroute/latest-hops-classified/{target}")
def traceroute_latest_hops_classified(target: str) -> list[dict[str, Any]]:
    normalized_target = _validate_peer_ip(target)
    return _fetch_all(
        """
        select
          measurement_id,
          target::text as target,
          target_label,
          measured_at,
          hop_number,
          hop_ip::text as hop_ip,
          responded,
          rtt_avg_ms,
          raw_line,
          ip_scope,
          effective_context_status,
          inventory_match_status,
          router_hostname,
          interface_name,
          interface_description,
          site_name,
          hop_classification,
          classification_confidence,
          classification_owner,
          classification_provider,
          classification_notes
        from v_active_traceroute_latest_hops_with_classification
        where target = %s::inet
        order by hop_number;
        """,
        (normalized_target,),
    )


@router.get("/measurements/traceroute/unmatched-private-hops")
def traceroute_unmatched_private_hops(limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          hop_ip::text as hop_ip,
          ip_scope,
          occurrences,
          distinct_targets,
          avg_rtt_avg_ms,
          first_seen,
          last_seen
        from v_active_traceroute_top_unmatched_private_hops
        order by occurrences desc, distinct_targets desc
        limit %s;
        """,
        (limit,),
    )


@router.get("/measurements/traceroute/classified-hops")
def traceroute_classified_hops(limit: int = Query(50, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          measurement_id,
          target::text as target,
          target_label,
          measured_at,
          hop_number,
          hop_ip::text as hop_ip,
          ip_scope,
          rtt_avg_ms,
          effective_context_status,
          hop_classification,
          classification_confidence,
          classification_provider,
          classification_notes,
          router_hostname,
          interface_name
        from v_active_traceroute_hops_enriched_with_classification
        where hop_classification is not null
        order by measured_at desc, target::text, hop_number
        limit %s;
        """,
        (limit,),
    )


@router.get("/measurements/traceroute/matched-hops")
def traceroute_matched_hops(limit: int = Query(50, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          target::text as target,
          target_label,
          measured_at,
          hop_number,
          hop_ip::text as hop_ip,
          ip_scope,
          rtt_avg_ms,
          router_hostname,
          router_role,
          router_management_ip::text as router_management_ip,
          interface_name,
          interface_description,
          interface_type,
          site_name,
          site_city
        from v_active_traceroute_latest_hops_enriched
        where inventory_match_status = 'MATCHED_INTERFACE'
        order by target::text, hop_number
        limit %s;
        """,
        (limit,),
    )


@router.get("/measurements/traceroute/latest-hops/{target}")
def traceroute_latest_hops(target: str) -> list[dict[str, Any]]:
    normalized_target = _validate_peer_ip(target)
    return _fetch_all(
        """
        select
          measurement_id,
          target::text as target,
          target_label,
          mode,
          measured_at,
          hop_number,
          hop_ip::text as hop_ip,
          responded,
          rtt_avg_ms,
          raw_line
        from v_active_traceroute_latest_hops
        where target = %s::inet
        order by hop_number;
        """,
        (normalized_target,),
    )


@router.get("/measurements/traceroute/private-hops")
def traceroute_private_hops(limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          measurement_id,
          target::text as target,
          hop_number,
          hop_ip::text as hop_ip,
          rtt_avg_ms,
          measured_at,
          raw_line
        from v_active_traceroute_private_hops
        order by measured_at desc, target::text, hop_number
        limit %s;
        """,
        (limit,),
    )


@router.get("/peers/ping")
def peers_ping(limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          observed_peer_ip::text as observed_peer_ip,
          observed_peer_asn,
          observed_routes,
          observed_prefixes,
          inventory_peer_name,
          inventory_connection_type,
          ixp_name,
          router_hostname,
          match_status,
          ping_status,
          packet_loss_percent,
          rtt_avg_ms,
          rtt_max_ms,
          ping_measured_at
        from v_bgp_peer_with_latest_ping
        order by
          case when ping_status is not null then 0 else 1 end,
          observed_routes desc,
          observed_peer_ip
        limit %s;
        """,
        (limit,),
    )


@router.get("/peers/ping/missing")
def peers_ping_missing(limit: int = Query(20, ge=1, le=200)) -> list[dict[str, Any]]:
    return _fetch_all(
        """
        select
          observed_peer_ip::text as observed_peer_ip,
          observed_peer_asn,
          observed_routes,
          observed_prefixes,
          match_status,
          inventory_peer_name,
          inventory_connection_type,
          ixp_name,
          router_hostname
        from v_bgp_peer_with_latest_ping
        where ping_status is null
        order by observed_routes desc, observed_peer_ip
        limit %s;
        """,
        (limit,),
    )


@router.get("/bgp/prefix")
def bgp_prefix_query(prefix: str = Query(..., min_length=1), limit: int = Query(20, ge=1, le=1000)) -> dict[str, Any]:
    return _call_operational_query(get_prefix_lookup, prefix, limit)


@router.get("/bgp/prefix/{prefix:path}")
def bgp_prefix_path(prefix: str = FastAPIPath(..., description="Prefixo CIDR, por exemplo 8.8.8.0/24")) -> dict[str, Any]:
    return _call_operational_query(get_prefix_lookup, prefix)


@router.get("/bgp/ip")
def bgp_ip_lookup(ip: str = Query(..., min_length=1)) -> dict[str, Any]:
    try:
        result = lookup_bgp_by_ip(ip)
    except ValueError as exc:
        _raise_operational_error(exc)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if result is None:
        return {
            "query": {"ip": ip, "type": "ip"},
            "ip": ip,
            "matched": False,
            "matched_prefix": None,
            "origin_asn": None,
            "origin_type": None,
            "match_route_count": 0,
            "peer_count": 0,
            "collector_count": 0,
            "sample_peers": [],
            "sample_as_paths": [],
            "summary": None,
            "current_routes": [],
            "peer_counts": [],
        }
    return {
        "matched": True,
        **result,
    }


@router.get("/bgp/visibility/ip/{ip}")
def bgp_visibility_by_ip(
    ip: str = FastAPIPath(..., min_length=1, description="IP a consultar"),
    asn: int | None = Query(None, ge=0),
    limit: int = Query(10, ge=1, le=50),
    include_paths: bool = Query(True),
    include_peers: bool = Query(True),
) -> dict[str, Any]:
    response = build_bgp_visibility_response(
        ip,
        asn=asn,
        limit=limit,
        include_paths=include_paths,
        include_peers=include_peers,
    )
    return sanitize_public_payload(response) if is_public_review_mode() else response


@router.get("/bgp/visibility/asn/{asn}/ip/{ip}")
def bgp_visibility_by_asn_and_ip(
    asn: int = FastAPIPath(..., ge=0),
    ip: str = FastAPIPath(..., min_length=1, description="IP a consultar"),
    limit: int = Query(10, ge=1, le=50),
    include_paths: bool = Query(True),
    include_peers: bool = Query(True),
) -> dict[str, Any]:
    return build_bgp_visibility_response(
        ip,
        asn=asn,
        limit=limit,
        include_paths=include_paths,
        include_peers=include_peers,
    )


@router.get("/bgp/asn/{asn}")
def bgp_asn_lookup(asn: int = FastAPIPath(..., ge=0), limit: int = Query(50, ge=1, le=100)) -> dict[str, Any]:
    return _call_operational_query(get_asn_lookup, asn, limit)


@router.get("/bgp/peer/{peer}")
def bgp_peer_lookup(
    peer: str = FastAPIPath(..., description="Peer IP ou ASN"),
    limit: int = Query(50, ge=1, le=100),
) -> dict[str, Any]:
    return _call_operational_query(get_peer_lookup, peer, limit)


@router.get("/bgp/top/changes")
def bgp_top_changes(
    limit: int = Query(20, ge=1, le=1000),
    change_type: str | None = Query(None),
    since_hours: int | None = Query(None, ge=1, le=8760),
) -> dict[str, Any]:
    return _call_operational_query(get_top_changes, limit, change_type, since_hours)


@router.get("/bgp/top/prefixes")
def bgp_top_prefixes(
    limit: int = Query(20, ge=1, le=1000),
    change_type: str | None = Query(None),
    since_hours: int | None = Query(None, ge=1, le=8760),
) -> dict[str, Any]:
    return _call_operational_query(get_top_prefixes, limit, change_type, since_hours)


@router.get("/bgp/top/origin-asns")
def bgp_top_origin_asns(
    limit: int = Query(20, ge=1, le=1000),
    change_type: str | None = Query(None),
    since_hours: int | None = Query(None, ge=1, le=8760),
) -> dict[str, Any]:
    return _call_operational_query(get_top_origin_asns, limit, change_type, since_hours)


@router.get("/bgp/top/peers")
def bgp_top_peers(
    limit: int = Query(20, ge=1, le=1000),
    change_type: str | None = Query(None),
    since_hours: int | None = Query(None, ge=1, le=8760),
) -> dict[str, Any]:
    return _call_operational_query(get_top_peers, limit, change_type, since_hours)


@router.get("/observed-destinations/top")
def observed_destinations_top(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    return {"items": list_top_observed_destinations(limit=limit)}


@router.get("/observed-destinations/asns")
def observed_destinations_asns(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    return {"items": list_top_observed_asns(limit=limit)}


@router.get("/observed-destinations/categories")
def observed_destinations_categories(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    return {"items": categories_summary(limit=limit)}


@router.get("/observed-destinations/summary")
def observed_destinations_summary() -> dict[str, Any]:
    return summarize_observed_destinations_ui()


@router.get("/observed-destinations/enrichment-pending")
def observed_destinations_pending(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    return {"items": list_unenriched_observed_destinations(limit=limit)}


@router.post("/observed-destinations/collect")
def observed_destinations_collect(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    limit = int(payload.get("limit", 1000))
    dry_run = bool(payload.get("dry_run", False))
    return collect_mikrotik_observed_destinations(limit=limit, dry_run=dry_run)


@router.post("/observed-destinations/enrich")
def observed_destinations_enrich(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    limit = int(payload.get("limit", 50))
    refresh = bool(payload.get("refresh", False))
    resolve_bgp = bool(payload.get("resolve_bgp", True))
    allow_external_asn = bool(payload.get("allow_external_asn", True))
    result = enrich_pending_observed_destinations(
        limit=limit,
        refresh=refresh,
        resolve_bgp=resolve_bgp,
        allow_external_asn=allow_external_asn,
    )
    return result


@router.get("/observed-destinations/ui")
def observed_destinations_ui() -> FileResponse:
    html_path = _STATIC_DIR / "observed_destinations.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="UI não encontrada.")
    return FileResponse(html_path)


@router.post("/observed-destinations/{ip}/promote")
def observed_destination_promote(ip: str = FastAPIPath(..., min_length=1), payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    result = promote_observed_destination_to_baseline(ip, confirm=bool(payload.get("confirm", False)), notes=payload.get("notes"))
    if result.get("status") != "ok":
        raise HTTPException(status_code=int(result.get("code") or 400), detail=result.get("detail") or "Falha ao promover destino.")
    return result


@router.get("/observed-destinations/baselines")
def observed_destination_baselines(limit: int = Query(50, ge=1, le=200), status: str | None = Query(None)) -> dict[str, Any]:
    return {"items": list_observed_destination_baselines(limit=limit, status=status)}


@router.get("/observed-destinations/baselines/{ip}")
def observed_destination_baseline_detail(ip: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    baseline = get_observed_destination_baseline(ip)
    if baseline is None:
        raise HTTPException(status_code=404, detail="Baseline não encontrada.")
    return sanitize_public_payload(baseline) if is_public_review_mode() else baseline


@router.post("/observed-destinations/baselines/{ip}/measure")
def observed_destination_baseline_measure(ip: str = FastAPIPath(..., min_length=1), payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    result = execute_baseline_active_measurement(
        ip,
        confirm=bool(payload.get("confirm", False)),
        include_ping=bool(payload.get("ping", True)),
        include_traceroute=bool(payload.get("traceroute", True)),
    )
    if result.get("status") not in {"ok", "partial"}:
        raise HTTPException(status_code=int(result.get("code") or 400), detail=result.get("detail") or "Falha ao executar medição ativa.")
    return result


@router.get("/observed-destinations/baselines/{ip}/measurements")
def observed_destination_baseline_measurements(ip: str = FastAPIPath(..., min_length=1), limit: int = Query(20, ge=1, le=100)) -> dict[str, Any]:
    baseline = get_observed_destination_baseline(ip)
    if baseline is None:
        raise HTTPException(status_code=404, detail="Baseline não encontrada.")
    response = {"items": get_baseline_measurements(ip, limit=limit)}
    return sanitize_public_payload(response) if is_public_review_mode() else response


@router.get("/observed-destinations/baselines/{ip}/traceroute-graph")
def observed_destination_baseline_traceroute_graph(ip: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    baseline = get_observed_destination_baseline(ip)
    if baseline is None:
        raise HTTPException(status_code=404, detail="Baseline não encontrada.")
    response = get_baseline_traceroute_graph(ip)
    return sanitize_public_payload(response) if is_public_review_mode() else response


@router.get("/observed-destinations/{ip}/report")
def observed_destination_report(ip: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    result = build_observed_destination_report(ip)
    if result.get("status") != "ok":
        raise HTTPException(status_code=int(result.get("code") or 400), detail=result.get("detail") or "Falha ao gerar relatório.")
    return sanitize_public_payload(result) if is_public_review_mode() else result


@router.get("/observed-destinations/trends-summary")
def observed_destination_trends_summary(window_runs: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    return {"status": "ok", "window_runs": window_runs, "summary": summarize_observed_destination_trends(window_runs=window_runs)}


@router.get("/observed-destinations/trends")
def observed_destination_trends(limit: int = Query(50, ge=1, le=100), window_runs: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    return {"status": "ok", "items": get_top_destination_trends(limit=limit, window_runs=window_runs)}


@router.get("/observed-destinations/trends/asns")
def observed_destination_trends_asns(limit: int = Query(50, ge=1, le=100), window_runs: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    return {"status": "ok", "items": get_asn_trends(limit=limit, window_runs=window_runs)}


@router.get("/observed-destinations/trends/categories")
def observed_destination_trends_categories(limit: int = Query(50, ge=1, le=100), window_runs: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    return {"status": "ok", "items": get_category_trends(limit=limit, window_runs=window_runs)}


@router.get("/observed-destinations/{ip}/trend")
def observed_destination_trend(ip: str = FastAPIPath(..., min_length=1), window_runs: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    row = get_observed_destination(ip)
    if row is None:
        raise HTTPException(status_code=404, detail="Destino observado não encontrado.")
    return {"status": "ok", **get_observed_destination_trend(ip, window_runs=window_runs)}


@router.get("/observed-destinations/{ip}")
def observed_destination_detail(ip: str = FastAPIPath(..., min_length=1)) -> dict[str, Any]:
    row = get_observed_destination(ip)
    if row is None:
        raise HTTPException(status_code=404, detail="Destino observado não encontrado.")
    ports = _fetch_all(
        """
        select destination_port, protocol, observation_count, first_seen, last_seen
        from observed_destinations
        where destination_ip = %s::inet
        order by observation_count desc, last_seen desc
        """,
        (ip,),
    )
    response = {
        "destination": row,
        "ports": ports,
        "suggested_priority": "high" if (row.get("observation_count") or 0) >= 10 else "normal",
        "suggested_monitoring_reason": (
            "alto volume observado"
            if (row.get("observation_count") or 0) >= 10
            else "destino observado para enriquecimento"
        ),
        "suggested_actions": [
            {"action": "resolve_dns", "requires_confirmation": False},
            {"action": "bgp_visibility", "requires_confirmation": False},
            {"action": "trace_route", "requires_confirmation": True},
            {"action": "generate_destination_report", "requires_confirmation": False},
            {"action": "promote_to_baseline", "requires_confirmation": True},
            {"action": "promote_to_monitoring", "requires_confirmation": True},
        ],
    }
    return sanitize_public_payload(response) if is_public_review_mode() else response
