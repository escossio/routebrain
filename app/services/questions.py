from __future__ import annotations

from datetime import datetime
import ipaddress
import re
from typing import Any

from app.services.learning_orchestrator import (
    ACTIVE_MEASUREMENT_POLICY,
    approve_learning_request,
    build_active_measurement_plan,
    build_answer,
    classify_target_ip,
    create_learning_request,
    execute_learning_request,
    get_learning_request,
    list_learning_requests,
    preview_active_measurement_targets,
    resolve_dns_for_domain,
    resolve_active_targets_for_request,
)
from app.services.observed_destinations import build_observed_destination_report, get_observed_destination, get_observed_destination_baseline
from app.services.observed_destination_baselines import get_latest_baseline_measurement
from app.services.bgp_operational_queries import lookup_bgp_by_ip
from app.services.external_enrichment import get_external_ip_enrichment
from app.services.external_route_inventory import compare_service_routes, get_service_route_summary, list_external_hops
from app.services.observed_destinations import resolve_observed_destination_asn_external
from app.services.asn_route_monitoring import (
    add_asn_monitoring_target,
    build_asn_route_change_answer,
    ensure_asn_monitoring_target,
    get_asn_baseline_summary,
    get_asn_monitoring_status,
    record_asn_snapshot,
)
from app.services.bgp_visibility import build_asn_ip_visibility_answer
from app.services.bgp_visibility import build_bgp_visibility_response
from app.services.action_planner import build_action_plan_for_question
from app.services.inventory_discovery import lookup_inventory_context_by_ip
from app.services.route_learning_builder import build_route_profile
from app.services.llm_assistant import (
    generate_conversational_answer,
    is_llm_assistant_enabled,
    should_use_llm_assistant,
)
try:  # pragma: no cover - optional runtime dependency
    from app.services.synthetic_browser_lab import run_synthetic_navigation
    from app.services.synthetic_dns_bgp_lab import analyze_synthetic_browser_bgp
except Exception:  # pragma: no cover - keep questions API usable without Playwright
    run_synthetic_navigation = None
    analyze_synthetic_browser_bgp = None
from app.services.traceroute_graph import get_traceroute_summary_for_learning_request

ACTIVE_TASK_TYPES = {"ping_measurement", "traceroute_measurement"}
ACTION_IDS = {
    "resolve_dns",
    "trace_route",
    "trace_route_with_inventory",
    "generate_destination_report",
    "discover_real_navigation_targets",
    "add_asn_to_monitoring",
    "generate_current_asn_snapshot",
    "show_current_asn_routes",
    "create_asn_route_report",
    "show_bgp_route_for_ip",
    "check_asn_in_as_path",
    "generate_asn_ip_visibility_report",
    "measure_baseline",
    "view_traceroute_graph",
    "promote_to_baseline",
}

EXPLICIT_ASN_RE = re.compile(r"\b(?:ASN|AS)\s*([1-9]\d{0,9})\b", re.IGNORECASE)
ROUTE_PROFILE_ENDPOINT = "/route-learning/sessions/demo/cloudflare/route-profile"
ROUTE_PROFILE_VISUAL_ENDPOINT = "/route-learning/sessions/demo/cloudflare/visual"
ROUTE_PROFILE_COMPARISON_ENDPOINT = "/route-learning/sessions/demo/cloudflare/learning-comparison-plan"
ROUTE_PROFILE_TEMPORAL_COMPARISON_ENDPOINT = "/route-learning/sessions/demo/cloudflare/temporal-comparison"
ROUTE_PROFILE_SERVICE = "cloudflare"
ROUTE_PROFILE_TARGET = "1.1.1.1"


def _safe_text(value: Any, fallback: str = "-") -> str:
    text = str(value).strip() if value is not None else ""
    return text or fallback


def build_ip_operational_answer(ip: str) -> dict[str, Any]:
    try:
        normalized_ip = str(ipaddress.ip_address(str(ip).strip()))
        ip_obj = ipaddress.ip_address(normalized_ip)
    except ValueError:
        return {
            "status": "error",
            "detail": "IP inválido.",
            "ip_operational": None,
            "operational_answer": "O IP informado é inválido.",
        }

    is_public = bool(
        not any(
            (
                ip_obj.is_private,
                ip_obj.is_loopback,
                ip_obj.is_link_local,
                ip_obj.is_multicast,
                ip_obj.is_reserved,
                ip_obj.is_unspecified,
                getattr(ip_obj, "is_site_local", False),
            )
        )
    )
    if not is_public:
        inventory_context = None
        try:
            inventory_context = lookup_inventory_context_by_ip(normalized_ip)
        except Exception:
            inventory_context = {"ip": normalized_ip, "status": "unknown", "hosts": [], "candidates": []}
        inventory_status = (inventory_context or {}).get("status")
        if inventory_status == "confirmed":
            host = ((inventory_context or {}).get("hosts") or [{}])[0]
            operational_answer = (
                f"O IP interno {normalized_ip} corresponde ao host confirmado {host.get('hostname') or '-'}"
                f" no site {host.get('site_code') or '-'}."
            )
        elif inventory_status == "candidate":
            candidate = ((inventory_context or {}).get("candidates") or [{}])[0]
            operational_answer = (
                f"O IP interno {normalized_ip} aparece como host candidato ainda não promovido"
                f" com confiança {candidate.get('confidence') or 0} por fonte {candidate.get('source_detail') or candidate.get('source') or '-'}."
            )
        else:
            operational_answer = (
                f"O IP {normalized_ip} não é público neste contexto; não vou tratá-lo como destino medível nem inferir ASN externo. "
                "Ele ainda não apareceu como host confirmado/candidato no inventário."
            )
        return {
            "status": "ok",
            "destination_ip": normalized_ip,
            "ip_operational": {
                "target_ip": normalized_ip,
                "is_public": False,
                "gaps": ["non_public_ip"],
            },
            "inventory_host_context": inventory_context,
            "operational_answer": operational_answer,
            "recommended_actions": [
                {"action": "generate_destination_report", "requires_confirmation": False},
            ],
        }

    bgp_local = None
    try:
        bgp_local = lookup_bgp_by_ip(normalized_ip, limit_peers=20)
    except Exception:
        bgp_local = None

    bgp_found = bool(bgp_local)
    bgp_prefix = bgp_local.get("matched_prefix") if bgp_local else None
    bgp_origin_asn = bgp_local.get("origin_asn") if bgp_local else None
    bgp_route_count = int(bgp_local.get("match_route_count") or 0) if bgp_local else 0
    bgp_peer_count = int(bgp_local.get("peer_count") or 0) if bgp_local else 0
    bgp_limitations = [] if bgp_found else ["no_bgp_match_for_ip"]

    destination = get_observed_destination(normalized_ip)
    report = None
    if destination is not None:
        try:
            report = build_observed_destination_report(normalized_ip)
        except Exception:
            report = None

    asn = destination.get("asn") if destination else None
    organization = destination.get("organization") if destination else None
    country = destination.get("country") if destination else None
    category = destination.get("category") if destination else None
    asn_source = destination.get("asn_source") if destination else None
    bgp_confirmed = bool(destination.get("bgp_confirmed")) if destination else False
    asn_confidence = destination.get("asn_confidence") if destination else None
    gaps: list[str] = []
    if not bgp_found:
        gaps.append("missing_bgp_match")

    if asn is None:
        try:
            external_ip = get_external_ip_enrichment(normalized_ip)
        except Exception:
            external_ip = None
        if external_ip and external_ip.get("asn") is not None:
            asn = int(external_ip["asn"])
            asn_source = str(external_ip.get("source") or "external")
            asn_confidence = "external_inferred"
            bgp_confirmed = False
            organization = organization or external_ip.get("organization_name") or external_ip.get("organization")
            country = country or external_ip.get("country")
        else:
            try:
                fallback = resolve_observed_destination_asn_external(normalized_ip)
            except Exception:
                fallback = None
            if fallback and fallback.get("matched") and fallback.get("asn") is not None:
                asn = int(fallback["asn"])
                asn_source = str(fallback.get("source") or "external")
                asn_confidence = "external_inferred"
                bgp_confirmed = False
                organization = organization or fallback.get("organization")
                country = country or fallback.get("country")

    if asn is not None and asn_source == "external" and not bgp_confirmed:
        gaps.append("external_asn_not_bgp_confirmed")

    baseline = get_observed_destination_baseline(normalized_ip)
    latest_measurement = get_latest_baseline_measurement(normalized_ip)
    if destination is None:
        gaps.append("missing_observed_destination")
    if baseline is None:
        gaps.append("missing_baseline")
    if latest_measurement is None:
        gaps.append("missing_active_measurement")

    ports = []
    if report and isinstance(report.get("observed"), dict):
        ports = report["observed"].get("ports") or []

    latest_ping = latest_measurement.get("ping_summary") if latest_measurement else None
    latest_traceroute = latest_measurement.get("traceroute_summary") if latest_measurement else None
    graph_available = bool(latest_measurement.get("graph_available")) if latest_measurement else False
    graph_url = f"/observed-destinations/baselines/{normalized_ip}/traceroute-graph" if graph_available else None

    if latest_measurement and latest_measurement.get("status") in {"ok", "partial"}:
        last_measurement_text = "A última medição salva indica o destino operacional."
    else:
        last_measurement_text = "Não há medição salva suficiente para afirmar o estado atual."

    bgp_text = (
        f"A tabela BGP local do RouteBrain encontrou o prefixo {bgp_prefix}."
        if bgp_found and bgp_prefix
        else "A tabela BGP local do RouteBrain não encontrou prefixo cobrindo esse IP."
    )
    asn_text = (
        f"Ele pertence ao ASN {asn} / {organization or '-'} por fonte {asn_source or 'unknown'}."
        if asn is not None
        else "Ainda não consegui confirmar ASN/organização para esse IP."
    )
    observed_text = (
        f"O IP já foi observado {destination.get('observation_count') or 0} vezes na MikroTik."
        if destination
        else "Ainda não encontrei esse IP nas coletas da MikroTik."
    )
    baseline_text = (
        f"Existe baseline ativa ({baseline.get('baseline_uid')})."
        if baseline
        else "Ainda não existe baseline para esse IP."
    )
    measurement_text = (
        f"Existe medição salva: ping {latest_ping.get('status') if isinstance(latest_ping, dict) else '-'}; "
        f"traceroute {latest_traceroute.get('status') if isinstance(latest_traceroute, dict) else '-'}."
        if latest_measurement
        else "Ainda não há medição/traceroute salvo."
    )

    operational_answer = " ".join(
        [
            f"Identifiquei o IP público {normalized_ip}.",
            asn_text,
            bgp_text,
            observed_text,
            baseline_text,
            measurement_text,
            last_measurement_text,
            "Posso executar nova medição ativa se você confirmar explicitamente.",
        ]
    )
    if report and isinstance(report.get("operational_report"), str):
        operational_answer = report["operational_report"]

    recommended_actions = [
        {"action": "generate_destination_report", "requires_confirmation": False},
        {"action": "show_bgp_route_for_ip", "requires_confirmation": False},
        {"action": "measure_baseline", "requires_confirmation": True},
        {"action": "view_traceroute_graph", "requires_confirmation": False},
    ]
    if baseline is None:
        recommended_actions.insert(0, {"action": "promote_to_baseline", "requires_confirmation": True})
    if destination is None:
        recommended_actions.append({"action": "trace_route", "requires_confirmation": True})

    return {
        "status": "ok",
        "destination_ip": normalized_ip,
        "operational_answer": operational_answer,
        "ip_operational": {
            "target_ip": normalized_ip,
            "is_public": True,
            "asn": asn,
            "organization": organization,
            "country": country,
            "category": category,
            "asn_source": asn_source,
            "bgp_confirmed": bgp_confirmed,
            "asn_confidence": asn_confidence,
            "bgp_route": {
                "found": bgp_found,
                "prefix": bgp_prefix,
                "origin_asn": bgp_origin_asn,
                "route_count": bgp_route_count,
                "peer_count": bgp_peer_count,
                "limitations": bgp_limitations,
            },
            "observed_destination": {
                "found": bool(destination),
                "observation_count": destination.get("observation_count") if destination else 0,
                "ports_protocols": ports,
            },
            "baseline": {
                "exists": baseline is not None,
                "baseline_uid": baseline.get("baseline_uid") if baseline else None,
                "status": baseline.get("status") if baseline else None,
                "promoted_at": baseline.get("promoted_at") if baseline else None,
            },
            "latest_measurement": {
                "exists": latest_measurement is not None,
                "ping_summary": latest_ping,
                "traceroute_summary": latest_traceroute,
                "graph_available": graph_available,
                "graph_url": graph_url,
            },
            "gaps": gaps,
        },
        "gaps": gaps,
        "recommended_actions": recommended_actions,
        "bgp_visibility": {
            "status": "ok" if bgp_found else "missing",
            "query": {"ip": normalized_ip, "asn": None, "prefix": bgp_prefix},
            "match": {
                "matched": bgp_found,
                "prefix": bgp_prefix,
                "origin_asn": bgp_origin_asn,
                "route_count": bgp_route_count,
                "peer_count": bgp_peer_count,
            },
            "limitations": bgp_limitations,
        },
        "baseline": {
            "baseline_exists": baseline is not None,
            "baseline_uid": baseline.get("baseline_uid") if baseline else None,
            "status": baseline.get("status") if baseline else None,
            "promoted_at": baseline.get("promoted_at") if baseline else None,
            "baseline_snapshot": baseline.get("baseline_snapshot") if baseline else {},
        },
        "measurements": {
            "ping_latest": latest_ping,
            "traceroute_latest": latest_traceroute,
            "traceroute_available": latest_measurement is not None,
            "active_measurement_required": latest_measurement is None,
        },
        "observed_destination": destination,
    }


def _safe_request_raw_context(request: dict[str, Any]) -> dict[str, Any]:
    raw_context = request.get("raw_context")
    return raw_context if isinstance(raw_context, dict) else {}


def _infer_operational_target(request: dict[str, Any], semantic_context: dict[str, Any] | None = None) -> dict[str, Any]:
    question = str(request.get("question") or request.get("normalized_question") or "").strip()
    lowered = question.lower()
    entities = request.get("_entities") if isinstance(request.get("_entities"), list) else []
    domain = None
    ip = None
    label = None
    needs_target_confirmation = False
    suggested_domain = False

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entity_type = str(entity.get("entity_type") or "").lower()
        value = str(entity.get("entity_value") or entity.get("normalized_value") or "").strip()
        if entity_type == "domain" and "." in value:
            domain = value.lower()
            break
        if entity_type == "ip" and value:
            ip = value
            break

    if not domain and not ip:
        if re.search(r"\bfacebook\b", lowered):
            label = "Facebook"
            domain = "facebook.com"
            needs_target_confirmation = True
            suggested_domain = True
        elif re.search(r"\bgoogle\b", lowered):
            label = "Google"
            domain = "google.com"
            needs_target_confirmation = True
            suggested_domain = True
        elif re.search(r"\bbaidu\b", lowered):
            label = "Baidu"
            domain = "baidu.com"
            needs_target_confirmation = True
            suggested_domain = True

    if domain and "." in domain and not suggested_domain:
        label = label or domain
        needs_target_confirmation = False

    if ip:
        label = label or ip

    return {
        "target_domain": domain,
        "target_ip": ip,
        "target_label": label,
        "entity_confidence": "confirmed" if (domain or ip) and not needs_target_confirmation else "suggested",
        "needs_target_confirmation": needs_target_confirmation,
    }


def _has_explicit_asn_marker(question: str) -> bool:
    return bool(EXPLICIT_ASN_RE.search(question or ""))


def _conversational_intent(question: str) -> str:
    lowered = " ".join(str(question or "").strip().lower().split())
    for source, target in {
        "á": "a",
        "à": "a",
        "ã": "a",
        "â": "a",
        "é": "e",
        "ê": "e",
        "í": "i",
        "ó": "o",
        "õ": "o",
        "ô": "o",
        "ú": "u",
        "ç": "c",
    }.items():
        lowered = lowered.replace(source, target)
    if lowered in {"ola", "oi", "opa", "bom dia", "boa tarde", "boa noite", "e ai", "eai"}:
        return "general_greeting"
    if lowered in {"teste", "test"}:
        return "general_test"
    if any(term in lowered for term in ("o que voce sabe fazer", "o que vc sabe fazer", "quais perguntas", "como pergunto", "me ajuda", "ajuda", "help")):
        return "help_prompt"
    return "conversational_help"


EXTERNAL_ROUTE_SERVICE_ALIASES: dict[str, tuple[str, ...]] = {
    "google": ("google", "gstatic", "googleapis"),
    "youtube": ("youtube", "googlevideo", "ytimg"),
    "facebook": ("facebook", "fbcdn"),
    "instagram": ("instagram", "cdninstagram"),
    "whatsapp": ("whatsapp", "web.whatsapp"),
    "netflix": ("netflix", "nflxvideo", "nflximg"),
    "cloudflare": ("cloudflare", "1.1.1.1"),
    "ptt": ("ptt", "ix.br", "ixbr", "ixp", "ix "),
}


def _external_route_services_from_question(question: str) -> list[str]:
    lowered = " ".join(str(question or "").lower().split())
    matches: list[str] = []
    for service_slug, aliases in EXTERNAL_ROUTE_SERVICE_ALIASES.items():
        if any(alias in lowered for alias in aliases):
            matches.append(service_slug)
    return matches


def _infer_external_route_intent(question: str, inferred: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    lowered = " ".join(str(question or "").lower().split())
    services = _external_route_services_from_question(question)
    if not services and not any(term in lowered for term in ("roteador", "roteadores", "hop", "hops", "asns", "asn", "ptt", "ix", "unknown", "desconhecid", "compare", "compar")):
        return None, {}
    route_terms = ("rota", "roteamento", "mape", "mapear", "traceroute", "trace", "inventari", "inventário")
    if any(term in lowered for term in ("desconhecid", "unknown hop", "unknown hops")):
        return "unknown_external_hops_query", {"service": None}
    if "ptt" in services or any(term in lowered for term in ("ptt", "ix.br", "ixbr", "ixp")):
        return "ptt_route_context_query", {"service": "ptt", "subject_service": services[0] if services else inferred.get("target_domain")}
    if len(services) >= 2 and any(term in lowered for term in ("mesmos asn", "mesmos asns", "compare", "compar", "passam pelos mesmos", "compartilham")):
        return "service_route_compare", {"service_a": services[0], "service_b": services[1]}
    if len(services) == 1:
        service = services[0]
        if any(term in lowered for term in route_terms):
            return "service_route_hops_query", {"service": service}
        if any(term in lowered for term in ("hops", "hop", "routers", "router")):
            return "service_route_hops_query", {"service": service}
        if any(term in lowered for term in ("roteadores",)):
            return "external_route_inventory_query", {"service": service}
        if any(term in lowered for term in ("asn", "asns")):
            return "external_route_inventory_query", {"service": service}
    return None, {}


def _infer_route_profile_intent(question: str, inferred: dict[str, Any]) -> dict[str, Any]:
    lowered = " ".join(str(question or "").lower().split())
    has_cloudflare = any(term in lowered for term in ("cloudflare", "1.1.1.1"))
    profile_terms = (
        "perfil",
        "rota",
        "roteamento",
        "evid",
        "asn",
        "tronco",
        "dedic",
        "limita",
        "falta",
        "confi",
        "completo",
        "sabemos",
        "aprend",
        "sabe",
    )
    temporal_change_terms = (
        "mudou",
        "mudanca",
        "mudança",
        "ao longo do tempo",
        "última medição",
        "ultima medicao",
        "histor",
        "comparação temporal",
        "comparacao temporal",
        "o que mudou",
    )
    baseline_status_terms = (
        "baseline",
        "baseline anterior",
        "serve como baseline",
        "já serve como baseline",
        "ja serve como baseline",
    )
    if not has_cloudflare and not ("perfil" in lowered and any(term in lowered for term in ("asn", "tronco", "dedic", "limita", "falta", "confi"))):
        return {"intent": None, "subtype": None, "service": None, "target": None}
    if not any(term in lowered for term in profile_terms) and not any(term in lowered for term in temporal_change_terms + baseline_status_terms):
        return {"intent": None, "subtype": None, "service": None, "target": None}

    subtype = "cloudflare_route_profile"
    if any(term in lowered for term in temporal_change_terms):
        subtype = "cloudflare_route_temporal_change"
    elif any(term in lowered for term in baseline_status_terms):
        subtype = "cloudflare_route_baseline_status"
    elif any(term in lowered for term in ("evid", "dedic")):
        subtype = "cloudflare_route_evidence"
    elif any(term in lowered for term in ("limita", "completo", "confi", "falta", "aprend")):
        subtype = "cloudflare_route_limitations"
    elif any(term in lowered for term in ("asn", "hops", "privad", "silenc", "colet")):
        subtype = "cloudflare_route_asn_gaps"
    elif any(term in lowered for term in ("tronco", "google")):
        subtype = "cloudflare_google_common_trunk"
    elif any(term in lowered for term in ("stale", "desatual", "atualiza", "refresh")):
        subtype = "cloudflare_route_staleness"

    target = str(
        inferred.get("target_ip")
        or inferred.get("target_domain")
        or inferred.get("target_label")
        or ROUTE_PROFILE_TARGET
    ).strip()
    if target in {"", "cloudflare", "Cloudflare"}:
        target = ROUTE_PROFILE_TARGET

    return {
        "intent": "route_profile_query",
        "subtype": subtype,
        "service": ROUTE_PROFILE_SERVICE,
        "target": target,
        "endpoint": ROUTE_PROFILE_ENDPOINT,
    }


def _conversational_examples() -> list[dict[str, Any]]:
    return [
        {
            "id": "example_ip_operational_check",
            "label": "Verificar IP operacional",
            "description": "Consulta contexto operacional read-only de um IP público.",
            "example_question": "verifica se o 8.8.8.8 está operacional",
            "risk": "read_only",
            "requires_confirmation": False,
            "enabled": True,
        },
        {
            "id": "example_route_to_domain",
            "label": "Ver rota para domínio",
            "description": "Analisa domínio, DNS e contexto de rota sem executar medição ativa.",
            "example_question": "qual rota para youtube.com",
            "risk": "read_only",
            "requires_confirmation": False,
            "enabled": True,
        },
        {
            "id": "example_asn_visibility",
            "label": "Consultar ASN/BGP",
            "description": "Mostra visibilidade ASN/IP a partir da base local do RouteBrain.",
            "example_question": "Me mostra como o ASN 15169 enxerga o IP 203.0.113.42",
            "risk": "read_only",
            "requires_confirmation": False,
            "enabled": True,
        },
    ]


def _local_agent_observability(response_type: str) -> dict[str, Any]:
    evidence_source = "routebrain_backend" if response_type == "local_operational" else "local_utility"
    return {
        "enabled": is_llm_assistant_enabled(),
        "used_agent": False,
        "provider": None,
        "model": None,
        "primary_agent": None,
        "final_agent": None,
        "handoffs": [],
        "tools_called": [],
        "guardrails_triggered": [],
        "safety_notes": [],
        "response_type": response_type,
        "active_action_executed": False,
        "evidence_source": evidence_source,
        "trace_available": False,
        "trace_id": None,
        "trace_safe_summary": {
            "summary": "Resposta local do RouteBrain; trace do Agents SDK não se aplica.",
        },
    }


def _build_conversational_question_response(question: str) -> dict[str, Any]:
    started = datetime.now().timestamp()
    assistant = generate_conversational_answer(question)
    answer = str(assistant.get("answer") or "")
    intent = _conversational_intent(question)
    agent_observability = assistant.get("agent_observability")
    if not isinstance(agent_observability, dict):
        agent_observability = {
            **_local_agent_observability("local_utility"),
            "enabled": is_llm_assistant_enabled(),
            "provider": "fallback",
            "response_type": "conversational_guidance",
            "evidence_source": "fallback",
        }
    guardrails_triggered = agent_observability.get("guardrails_triggered") or []
    display_question = (
        "[pergunta redigida por conter segredo]"
        if "blocked_sensitive_input" in guardrails_triggered
        else question
    )
    compact = {
        "request_uid": None,
        "question": display_question,
        "intent": intent,
        "status": "completed",
        "consent_status": "not_required",
        "answer": answer,
        "operational_answer": answer,
        "active_action_executed": False,
        "semantic_context": {},
        "gaps": [],
        "evidence_summary": [],
        "traceroute": {"available": False, "reason": "not_applicable"},
        "active_measurements": {
            "required": False,
            "consent_status": "not_required",
            "can_approve": False,
            "can_execute": False,
            "tasks": [],
            "warnings": [],
            "estimated_runtime_seconds": 0,
            "blocked_targets": [],
            "skipped_targets": [],
        },
        "recommended_actions": _conversational_examples(),
        "target_context": {},
        "asn_monitoring": None,
        "asn_route_change": None,
        "bgp_visibility": None,
        "ip_operational": None,
        "operational_intent": intent,
        "llm_assistant": {
            "enabled": is_llm_assistant_enabled(),
            "used_llm": bool(assistant.get("used_llm")),
            "provider": assistant.get("provider"),
            "model": assistant.get("model"),
            "fallback": not bool(assistant.get("used_llm")),
            "error": assistant.get("error"),
            "suggested_questions": assistant.get("suggested_questions") or [],
            "intent_hint": assistant.get("intent_hint"),
            "safety_notes": assistant.get("safety_notes") or [],
            "suggested_action_plan": assistant.get("suggested_action_plan"),
        },
        "agent_observability": agent_observability,
        "action_plan": None,
        "debug_context": {},
        "warnings": [],
        "elapsed_seconds": round(max(0.0, datetime.now().timestamp() - started), 3),
        "links": {},
    }
    compact["action_plan"] = build_action_plan_for_question(compact)
    return compact


def _infer_asn_route_target(question: str, request: dict[str, Any], inferred_target: dict[str, Any]) -> dict[str, Any]:
    lowered = question.lower()
    entities = request.get("_entities") if isinstance(request.get("_entities"), list) else []
    asn = None
    asn_label = None
    route_change_terms = ("mudança de roteamento", "mudanca de roteamento", "mudança de rota", "mudanca de rota", "route change", "routing change", "alteração de rota", "alteracao de rota", "mudou o roteamento", "teve mudança de rota", "teve mudanca de rota", "monitora mudança de rota", "monitora mudanca de rota", "verificar se houve mudança", "verificar se houve mudanca")
    monitoring_terms = ("monitora", "monitoramento", "acompanha", "acompanhar", "adiciona", "adicionar")
    asn_match = EXPLICIT_ASN_RE.search(question)
    if asn_match:
        asn = int(asn_match.group(1))
    else:
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            if entity.get("entity_type") == "asn":
                try:
                    asn = int(entity.get("normalized_value") or entity.get("entity_value"))
                    break
                except (TypeError, ValueError):
                    continue
    if "google" in lowered and asn is None:
        asn_label = "Google"
    if asn is None and not _has_explicit_asn_marker(question):
        return {
            "intent": None,
            "asn": None,
            "label": None,
            "needs_monitoring_confirmation": False,
            "route_change_query": False,
        }
    route_change_query = any(term in lowered for term in route_change_terms) or ("roteamento" in lowered and asn is not None)
    monitoring_request = any(term in lowered for term in monitoring_terms) and asn is not None and not route_change_query
    if asn is None:
        return {
            "intent": None,
            "asn": None,
            "label": None,
            "needs_monitoring_confirmation": False,
            "route_change_query": False,
        }
    label = asn_label
    if "google" in lowered:
        label = "Google"
    elif "cloudflare" in lowered:
        label = "Cloudflare"
    return {
        "intent": "asn_route_monitoring_request" if monitoring_request else "asn_route_change_check" if route_change_query else "asn_route_monitoring_request",
        "asn": asn,
        "label": label,
        "needs_monitoring_confirmation": True,
        "route_change_query": route_change_query,
    }


def _infer_bgp_visibility_target(question: str, request: dict[str, Any]) -> dict[str, Any]:
    lowered = question.lower()
    entities = request.get("_entities") if isinstance(request.get("_entities"), list) else []
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
        "caminho do asn",
        "rota para o ip",
        "vê o ip",
        "enxerga o ip",
        "aparece no caminho",
        "aparece no as path",
        "aparece no caminho para",
    )
    if not any(term in lowered for term in visibility_terms):
        return {"intent": None, "asn": None, "target_ip": None, "target_prefix": None, "target_kind": None}

    asn = None
    ip = None
    prefix = None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entity_type = str(entity.get("entity_type") or "").lower()
        value = str(entity.get("normalized_value") or entity.get("entity_value") or "").strip()
        if entity_type == "asn" and asn is None:
            try:
                asn = int(value)
            except (TypeError, ValueError):
                pass
        elif entity_type == "ip" and ip is None:
            ip = value
        elif entity_type == "prefix" and prefix is None:
            prefix = value

    if asn is None:
        asn_match = EXPLICIT_ASN_RE.search(question)
        if asn_match:
            asn = int(asn_match.group(1))

    if ip is None:
        ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", question)
        if ip_match:
            ip = ip_match.group(0)
    if prefix is None:
        prefix_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", question)
        if prefix_match:
            prefix = prefix_match.group(0)

    if asn is None or (ip is None and prefix is None):
        return {"intent": None, "asn": asn, "target_ip": ip, "target_prefix": prefix, "target_kind": None}

    return {
        "intent": "bgp_asn_ip_visibility",
        "asn": asn,
        "target_ip": ip,
        "target_prefix": prefix,
        "target_kind": "ip" if ip else "prefix",
    }


def _infer_operator_intent(question: str, inferred: dict[str, Any]) -> str | None:
    lowered = question.lower()
    nav_terms = (
        "simular acesso",
        "acesso real",
        "abrir site",
        "navegar",
        "devtools",
        "har",
        "aplicação web",
        "aplicacao web",
        "vamos simular",
        "simula acesso",
    )
    if any(term in lowered for term in nav_terms):
        return "real_access_simulation" if inferred.get("target_domain") else "synthetic_navigation_discovery"
    if inferred.get("target_label") and not inferred.get("target_domain") and not inferred.get("target_ip"):
        return "synthetic_navigation_discovery"
    return None


def _question_kind(request: dict[str, Any]) -> str:
    intent = str(request.get("intent") or "").lower()
    question = str(request.get("question") or "").lower()
    if intent in {
        "external_route_inventory_query",
        "service_route_hops_query",
        "service_route_compare",
        "unknown_external_hops_query",
        "ptt_route_context_query",
    }:
        return "inventory"
    if intent == "bgp_asn_ip_visibility":
        return "bgp_visibility"
    if intent in {"ip_operational_check", "route_to_ip"}:
        return "ip_operational"
    if intent in {"domain_analysis", "route_to_domain"}:
        return "destination"
    if "ptt-ce" in question or "ix.br" in question or "ixbr" in question:
        return "inventory"
    has_asn = bool(re.search(r"\b(?:asn|as)\b", question) and re.search(r"\b[1-9]\d{0,9}\b", question))
    has_ip_or_prefix = bool(re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", question))
    has_domain = bool(re.search(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b", question, re.IGNORECASE))
    route_change_terms = ("routing change", "route change", "mudança de rota", "mudanca de rota", "mudança de roteamento", "mudanca de roteamento", "alteração de rota", "alteracao de rota", "mudou o roteamento", "teve mudança de rota", "teve mudanca de rota")
    if any(term in question for term in route_change_terms) or (has_asn and "roteamento" in question):
        return "asn_route"
    if has_ip_or_prefix and not has_asn:
        return "ip_operational"
    if has_domain and "roteamento" in question and not has_asn and not has_ip_or_prefix:
        return "destination"
    if any(term in question for term in ("simular acesso", "acesso real", "abrir site", "devtools", "har", "navegar")):
        return "synthetic_navigation"
    return "general"


def _question_kind_from_intent(request: dict[str, Any], operator_intent: str | None) -> str:
    if operator_intent in {
        "external_route_inventory_query",
        "service_route_hops_query",
        "service_route_compare",
        "unknown_external_hops_query",
        "ptt_route_context_query",
    }:
        return "inventory"
    if operator_intent in {"real_access_simulation", "synthetic_navigation_discovery"}:
        return "synthetic_navigation"
    if operator_intent == "bgp_asn_ip_visibility":
        return "bgp_visibility"
    if operator_intent in {"ip_operational_check", "route_to_ip"}:
        return "ip_operational"
    return _question_kind(request)


def _action_templates(target_info: dict[str, Any], active: dict[str, Any], question_kind: str) -> list[dict[str, Any]]:
    has_confirmed_target = bool(target_info.get("target_domain") or target_info.get("target_ip"))
    needs_confirmation = bool(target_info.get("needs_target_confirmation"))
    trace_enabled = has_confirmed_target and not needs_confirmation
    actions: list[dict[str, Any]] = []

    def add(action: dict[str, Any]) -> None:
        if action.get("enabled"):
            actions.append(action)

    if question_kind in {"destination", "general", "ip_operational"} and has_confirmed_target:
        add(
            {
                "id": "resolve_dns",
                "label": "Resolver DNS",
                "description": "Identificar os IPs atuais do domínio.",
                "requires_confirmation": False,
                "risk": "safe_read_only",
                "enabled": bool(target_info.get("target_domain") or target_info.get("target_ip") or target_info.get("target_label")),
            }
        )
        add(
            {
                "id": "trace_route",
                "label": "Traçar rota sem inventariar hosts",
                "description": "Executar traceroute/ping para IP público permitido, sem cadastrar hops no inventário.",
                "requires_confirmation": True,
                "risk": "active_measurement",
                "enabled": trace_enabled,
            }
        )
        add(
            {
                "id": "trace_route_with_inventory",
                "label": "Traçar rota e inventariar/enriquecer hosts",
                "description": "Executar rota e enriquecer hops com RDAP/ASN/classificação, sem confirmar host interno automaticamente.",
                "requires_confirmation": True,
                "risk": "active_measurement_and_enrichment",
                "enabled": trace_enabled,
            }
        )
        add(
            {
                "id": "generate_destination_report",
                "label": "Gerar relatório do destino",
                "description": "Consolidar DNS, BGP, memória, medições e lacunas em um relatório.",
                "requires_confirmation": False,
                "risk": "read_only_report",
                "enabled": True,
            }
        )
        if question_kind == "ip_operational":
            add(
                {
                    "id": "show_bgp_route_for_ip",
                    "label": "Ver rota BGP do IP",
                    "description": "Consultar o prefixo e a rota observada para o IP informado.",
                    "requires_confirmation": False,
                    "risk": "read_only",
                    "enabled": True,
                }
            )
            if has_confirmed_target:
                add(
                    {
                        "id": "view_traceroute_graph",
                        "label": "Ver caminho da rota",
                        "description": "Abrir o grafo da última medição salva para o IP.",
                        "requires_confirmation": False,
                        "risk": "read_only",
                        "enabled": True,
                    }
                )
            add(
                {
                    "id": "measure_baseline",
                    "label": "Medir baseline",
                    "description": "Executar ping/traceroute sob confirmação explícita para a baseline promovida.",
                    "requires_confirmation": True,
                    "risk": "active_measurement",
                    "enabled": True,
                }
            )
            if not has_confirmed_target:
                add(
                    {
                        "id": "promote_to_baseline",
                        "label": "Promover para baseline",
                        "description": "Criar baseline para o IP observado antes de medir.",
                        "requires_confirmation": True,
                        "risk": "state_change_baseline",
                        "enabled": True,
                    }
                )

    if question_kind == "synthetic_navigation":
        add(
            {
                "id": "discover_real_navigation_targets",
                "label": "Identificar destinos reais via navegação",
                "description": "Usar automação de navegador/DevTools para descobrir quais domínios e IPs aparecem durante o acesso real.",
                "requires_confirmation": True,
                "risk": "synthetic_browser_navigation",
                "enabled": True,
            }
        )
        if has_confirmed_target:
            add(
                {
                    "id": "resolve_dns",
                    "label": "Resolver DNS",
                    "description": "Identificar os IPs atuais do domínio.",
                    "requires_confirmation": False,
                    "risk": "safe_read_only",
                    "enabled": True,
                }
            )
            if trace_enabled:
                add(
                    {
                        "id": "trace_route",
                        "label": "Traçar rota sem inventariar hosts",
                        "description": "Executar traceroute/ping para IP público permitido, sem cadastrar hops no inventário.",
                        "requires_confirmation": True,
                        "risk": "active_measurement",
                        "enabled": True,
                    }
                )
                add(
                    {
                        "id": "trace_route_with_inventory",
                        "label": "Traçar rota e inventariar/enriquecer hosts",
                        "description": "Executar rota e enriquecer hops com RDAP/ASN/classificação, sem confirmar host interno automaticamente.",
                        "requires_confirmation": True,
                        "risk": "active_measurement_and_enrichment",
                        "enabled": True,
                    }
                )
        add(
            {
                "id": "generate_destination_report",
                "label": "Gerar relatório do destino",
                "description": "Consolidar DNS, BGP, memória, medições e lacunas em um relatório.",
                "requires_confirmation": False,
                "risk": "read_only_report",
                "enabled": True,
            }
        )

    if question_kind == "asn_route" and target_info.get("asn") is not None:
        add(
            {
                "id": "add_asn_to_monitoring",
                "label": "Adicionar ASN ao monitoramento",
                "description": "Criar linha de base a partir de agora para detectar mudanças futuras.",
                "requires_confirmation": True,
                "risk": "state_change_monitoring",
                "enabled": True,
            }
        )
        add(
            {
                "id": "generate_current_asn_snapshot",
                "label": "Gerar snapshot atual do ASN",
                "description": "Registrar visão atual de rotas/prefixos/peers como baseline inicial.",
                "requires_confirmation": True,
                "risk": "state_change_baseline",
                "enabled": True,
            }
        )
        add(
            {
                "id": "show_current_asn_routes",
                "label": "Ver rotas atuais do ASN",
                "description": "Consultar rotas, prefixos e peers atuais sem alterar estado.",
                "requires_confirmation": False,
                "risk": "read_only",
                "enabled": True,
            }
        )
        add(
            {
                "id": "create_asn_route_report",
                "label": "Gerar relatório do ASN",
                "description": "Consolidar baseline, estado atual e diferenças observadas.",
                "requires_confirmation": False,
                "risk": "read_only_report",
                "enabled": True,
            }
        )

    if question_kind == "bgp_visibility" and target_info.get("asn") is not None:
        add(
            {
                "id": "show_bgp_route_for_ip",
                "label": "Ver rota BGP do IP",
                "description": "Consultar o prefixo e a rota observada para o IP informado.",
                "requires_confirmation": False,
                "risk": "read_only",
                "enabled": True,
            }
        )
        add(
            {
                "id": "check_asn_in_as_path",
                "label": "Verificar ASN no AS path",
                "description": "Checar se o ASN consultado aparece no caminho observado.",
                "requires_confirmation": False,
                "risk": "read_only",
                "enabled": True,
            }
        )
        add(
            {
                "id": "generate_asn_ip_visibility_report",
                "label": "Gerar relatório ASN/IP",
                "description": "Consolidar prefixo, origem, peers, AS paths e limitações.",
                "requires_confirmation": False,
                "risk": "read_only_report",
                "enabled": True,
            }
        )
        add(
            {
                "id": "add_asn_to_monitoring",
                "label": "Adicionar ASN ao monitoramento",
                "description": "Monitorar mudanças futuras desse ASN sem afetar a análise atual.",
                "requires_confirmation": True,
                "risk": "state_change_monitoring",
                "enabled": True,
            }
        )

    if question_kind == "inventory":
        add(
            {
                "id": "generate_destination_report",
                "label": "Gerar relatório do destino",
                "description": "Consolidar contexto público em um relatório.",
                "requires_confirmation": False,
                "risk": "read_only_report",
                "enabled": True,
            }
        )

    if question_kind == "general" and not has_confirmed_target and target_info.get("asn") is None:
        return []

    return actions


def _build_operational_answer(
    request: dict[str, Any],
    inferred: dict[str, Any],
    answer: dict[str, Any],
    active: dict[str, Any],
    traceroute: dict[str, Any],
    semantic_context: dict[str, Any] | None,
    gaps: list[dict[str, Any]],
    resolved_ips: list[str],
) -> str:
    request_kind = _question_kind(request)
    domain = inferred.get("target_domain")
    ip = inferred.get("target_ip")
    label = inferred.get("target_label")
    question = str(request.get("question") or "").strip()
    external_route_intent, external_route_context = _infer_external_route_intent(question, inferred)
    if request_kind == "inventory" and external_route_intent:
        request_kind = "external_route_inventory"
    if external_route_intent in {
        "external_route_inventory_query",
        "service_route_hops_query",
        "service_route_compare",
        "unknown_external_hops_query",
        "ptt_route_context_query",
    }:
        services = _external_route_services_from_question(question)
        service_ref = external_route_context.get("service")
        if not service_ref and services:
            service_ref = services[0]
        if not service_ref:
            service_ref = inferred.get("service")
        service_slug = str(service_ref or "").strip().lower()
        if external_route_intent == "service_route_compare":
            service_a = str(external_route_context.get("service_a") or (services[0] if len(services) >= 1 else "")).strip().lower()
            service_b = str(external_route_context.get("service_b") or (services[1] if len(services) >= 2 else "")).strip().lower()
            if not service_a or not service_b:
                return "Preciso de dois serviços para comparar. Ingerir traceroutes já existentes pode ajudar, mas não vou executar medição nova automaticamente."
            comparison = compare_service_routes(service_a, service_b)
            overlap = (comparison.get("comparison") or {}).get("overlap") or {}
            shared_asns = overlap.get("shared_asn_count", 0)
            shared_hops = overlap.get("shared_hop_count", 0)
            return (
                f"Comparei {service_a} e {service_b}: compartilham {shared_hops} hops e {shared_asns} ASNs na base atual. "
                "Se o inventário estiver vazio para algum deles, preciso ingerir traceroutes existentes ou medir traceroute para esse serviço; não vou executar isso automaticamente."
            )
        if external_route_intent == "unknown_external_hops_query":
            unknown_hops = list_external_hops(limit=20, unknown_only=True)
            if not unknown_hops:
                return "Não encontrei hops externos desconhecidos no inventário atual. Se houver traceroutes salvos sem enriquecimento, preciso ingerir ou enriquecer esses dados."
            sample = ", ".join(str(row.get("hop_ip")) for row in unknown_hops[:5] if row.get("hop_ip"))
            return f"Há {len(unknown_hops)} hops externos ainda desconhecidos no inventário atual. Exemplos: {sample}. Posso enriquecer os hops já existentes, sem medir nada novo."
        if external_route_intent == "ptt_route_context_query":
            ptt_summary = get_service_route_summary("ptt")
            hops = (ptt_summary.get("hops") or [])[:5] if isinstance(ptt_summary, dict) else []
            if not hops or ptt_summary.get("summary", {}).get("hop_count", 0) == 0:
                return "Ainda não há contexto suficiente de PTT/IX no inventário externo. Preciso ingerir traceroutes já existentes ou contexto IX público para responder, sem executar nova medição automaticamente."
            sample = ", ".join(str(row.get("hop_ip")) for row in hops if row.get("hop_ip"))
            return f"Encontrei contexto PTT/IX no inventário externo. Exemplos de hops/ASNs observados: {sample}. Posso detalhar o serviço ptt com os traceroutes já salvos."
        if not service_slug:
            return "Preciso de um serviço explícito para consultar o inventário externo. Se não houver dados, preciso ingerir traceroutes já existentes ou medir traceroute para esse serviço, sem executar automaticamente."
        summary_response = get_service_route_summary(service_slug)
        summary = summary_response.get("summary") or {}
        hops = summary_response.get("hops") or []
        hop_count = int(summary.get("hop_count") or 0)
        if hop_count == 0:
            return (
                f"Ainda não há dados externos suficientes para {service_slug}. "
                "Preciso ingerir traceroutes já existentes ou medir traceroute para esse serviço; não vou executar automaticamente."
            )
        sample_hops = ", ".join(str(row.get("hop_ip")) for row in hops[:5] if row.get("hop_ip"))
        return (
            f"O inventário externo de {service_slug} tem {hop_count} hops e {int(summary.get('distinct_asn_count') or 0)} ASNs distintos. "
            f"Exemplos: {sample_hops}. "
            "Se algum hop ainda estiver desconhecido, posso enriquecer os hops já existentes sem executar nova medição."
        )
    if request_kind == "inventory":
        return "Não tratei essa pergunta como medição de destino. Posso responder com inventário e contexto público do PTT-CE, ou gerar um relatório do contexto atual."
    if request_kind == "ip_operational":
        report = build_ip_operational_answer(str(ip or ""))
        return str(report.get("operational_answer") or f"Identifiquei o IP {ip}. Posso gerar relatório operacional, verificar rota BGP local e, se necessário, executar medição ativa mediante confirmação.")
    if request_kind == "bgp_visibility":
        visibility = answer.get("bgp_visibility") if isinstance(answer.get("bgp_visibility"), dict) else {}
        asn = inferred.get("asn")
        ip = inferred.get("target_ip") or inferred.get("target_prefix")
        if not visibility:
            return (
                f"Consigo consultar como o RouteBrain enxerga {ip or 'o destino informado'} na base BGP, "
                f"mas não consegui estruturar evidência suficiente para afirmar a visão do ASN {asn}."
            )
        prefix = visibility.get("matched_prefix")
        origin_asn = visibility.get("origin_asn")
        direct_view = visibility.get("direct_view_available")
        asn_is_origin = visibility.get("asn_is_origin")
        asn_seen_in_as_path = visibility.get("asn_seen_in_as_path")
        if prefix:
            base = f"O IP {ip} está coberto pelo prefixo {prefix}"
            if origin_asn is not None:
                base += f", originado pelo ASN {origin_asn}"
            base += ". "
        else:
            base = f"Não encontrei um prefixo coberto para {ip}. "
        if direct_view is True:
            view_text = f"Tenho visão direta do ASN {asn} como ponto de observação nessa cobertura. "
        else:
            view_text = (
                f"Não tenho visão direta do ASN {asn} como ponto de observação nessa cobertura; "
                "a leitura é inferida pelos AS paths e peers observados pelo RouteBrain. "
            )
        if asn_is_origin is True:
            origin_text = f"O ASN {asn} é a origem observada desse prefixo. "
        elif asn_is_origin is False:
            origin_text = f"O ASN {asn} não aparece como origem desse prefixo. "
        else:
            origin_text = f"Não consegui afirmar se o ASN {asn} é a origem desse prefixo. "
        if asn_seen_in_as_path is True:
            path_text = f"O ASN {asn} aparece em pelo menos um AS path observado. "
        elif asn_seen_in_as_path is False:
            path_text = f"Não encontrei o ASN {asn} nos AS paths amostrados. "
        else:
            path_text = f"Não consegui confirmar a presença do ASN {asn} nos AS paths observados. "
        return base + view_text + origin_text + path_text + "Posso gerar um relatório ASN/IP ou inspecionar a rota BGP do IP."
    if request_kind == "asn_route":
        asn = inferred.get("asn")
        label = inferred.get("target_label") or inferred.get("target_domain") or inferred.get("target_ip")
        monitoring = answer.get("asn_route_monitoring") if isinstance(answer.get("asn_route_monitoring"), dict) else {}
        if answer.get("route_change_analysis_status") == "missing_baseline" or not monitoring.get("baseline_exists"):
            return (
                f"Eu ainda não consigo afirmar se houve mudança de roteamento para o ASN {asn}, porque não tenho uma linha de base histórica suficiente desse ASN em monitoramento. "
                f"Posso adicionar o ASN {asn} ao monitoramento agora; a partir das próximas coletas, consigo detectar alterações de prefixos, peers e caminhos. "
                "Sou esperto, mas ainda não tenho bola mágica, meu querido operador."
            )
        if label:
            return (
                f"O ASN {asn} já está em monitoramento. Posso comparar baseline e estado atual para estimar mudanças de roteamento. "
                f"Se você quiser, também posso manter o ASN {asn} sob observação contínua."
            )
        return f"O ASN {asn} já está em monitoramento e posso comparar baseline com o estado atual."
    if request_kind == "synthetic_navigation":
        if label and domain:
            return (
                f"Para simular um acesso real ao {label}, primeiro preciso descobrir quais destinos são acionados durante a navegação. "
                f"Posso usar automação de navegador/DevTools para identificar domínios e IPs reais. Depois disso, posso resolver DNS, verificar BGP, "
                f"traçar rota e gerar um relatório."
            )
        return (
            "Para simular um acesso real, primeiro preciso descobrir quais destinos são acionados durante a navegação. "
            "Posso usar automação de navegador/DevTools para identificar domínios e IPs reais. Depois disso, posso resolver DNS, verificar BGP, "
            "traçar rota e gerar um relatório."
        )
    if not domain and not ip:
        if label:
            return f"Interpretei {label} como possível destino {domain}. Confirme antes de medir. Posso resolver DNS, traçar rota ou gerar um relatório."
        return "Não identifiquei um destino técnico específico na pergunta. Informe um domínio ou IP, ou escolha uma ação para investigar."
    if domain and inferred.get("needs_target_confirmation"):
        return f"Interpretei {label} como possível destino {domain}. Confirme antes de medir. Posso resolver DNS agora; depois posso traçar rota e, se você quiser, enriquecer os hops encontrados."
    if domain:
        parts = []
        if resolved_ips:
            parts.append(f"O domínio {domain} resolve para {', '.join(resolved_ips)}.")
        else:
            parts.append(f"O destino {domain} já está identificado.")
        if traceroute.get("available"):
            parts.append("Há traceroute recente disponível.")
        else:
            parts.append("Ainda não há traceroute recente.")
        if active.get("required"):
            parts.append("Posso executar uma medição ativa para verificar latência e caminho.")
        else:
            parts.append("Posso resolver DNS ou gerar um relatório do destino.")
        return " ".join(parts)
    if ip:
        return f"O destino informado parece ser o IP {ip}. Posso gerar relatório, resolver contexto BGP e, se confirmado, executar medição ativa."
    return "Não identifiquei um destino técnico específico na pergunta. Informe um domínio ou IP, ou escolha uma ação para investigar."


def answer_route_profile_question(question: str, profile: dict[str, Any], profile_query: dict[str, Any] | None = None) -> dict[str, Any]:
    query = profile_query if isinstance(profile_query, dict) else {}
    route_summary = profile.get("route_summary") if isinstance(profile.get("route_summary"), dict) else {}
    temporal_comparison = profile.get("temporal_comparison") if isinstance(profile.get("temporal_comparison"), dict) else {}
    profile_metadata = profile.get("metadata") if isinstance(profile.get("metadata"), dict) else {}
    route_profile_summary = {
        "profile_uid": profile.get("profile_uid"),
        "status": profile.get("status"),
        "learned_from": profile.get("learned_from"),
        "route_summary": route_summary,
        "path_signature": profile.get("path_signature") if isinstance(profile.get("path_signature"), dict) else {},
        "counting_semantics": profile.get("counting_semantics") if isinstance(profile.get("counting_semantics"), dict) else {},
        "confidence": profile.get("confidence"),
        "limitations": profile.get("limitations") or [],
        "remaining_ignorance": profile.get("remaining_ignorance") or [],
        "asn_attribution_status": profile.get("asn_attribution_status") if isinstance(profile.get("asn_attribution_status"), dict) else {},
        "reuse_policy": profile.get("reuse_policy") if isinstance(profile.get("reuse_policy"), dict) else {},
        "comparison_policy": profile.get("comparison_policy") if isinstance(profile.get("comparison_policy"), dict) else {},
        "temporal_comparison": temporal_comparison,
        "measurement_context": profile_metadata.get("measurement_context") if isinstance(profile_metadata.get("measurement_context"), dict) else {},
        "source_endpoints": [
            ROUTE_PROFILE_ENDPOINT,
            ROUTE_PROFILE_VISUAL_ENDPOINT,
            ROUTE_PROFILE_COMPARISON_ENDPOINT,
            ROUTE_PROFILE_TEMPORAL_COMPARISON_ENDPOINT,
        ],
    }
    learned_from = route_profile_summary["learned_from"] if isinstance(route_profile_summary.get("learned_from"), dict) else {}
    asn_status = route_profile_summary["asn_attribution_status"] if isinstance(route_profile_summary.get("asn_attribution_status"), dict) else {}
    remaining_types = [item.get("type") for item in route_profile_summary.get("remaining_ignorance") or [] if isinstance(item, dict)]
    limitations = route_profile_summary.get("limitations") or []
    subtype = str(query.get("subtype") or "cloudflare_route_profile")

    common_answer = (
        f"Temos um perfil de rota Cloudflare baseado na run dedicada {_safe_text(learned_from.get('dedicated_run_uid'))}."
        f" Observamos {_safe_text(route_summary.get('logical_hop_count') or route_summary.get('hop_count'), '0')} posições lógicas, "
        f"({_safe_text(route_summary.get('responding_hop_count') or asn_status.get('responding_hop_count'), '0')} respondentes e {_safe_text(route_summary.get('silent_hop_count') or asn_status.get('silent_hop_count'), '0')} silenciosas), "
        f"com {_safe_text(route_summary.get('edge_count'), '0')} edges."
    )
    if subtype == "cloudflare_route_evidence":
        answer = (
            f"{common_answer} Há evidência dedicada persistida e o perfil continua read-only. "
            "A execução ativa já aconteceu no passado; nesta resposta nada é executado."
        )
    elif subtype == "cloudflare_route_temporal_change":
        if temporal_comparison.get("baseline_availability", {}).get("status") == "missing":
            answer = (
                "Não dá para afirmar mudança temporal ainda. "
                f"O RouteBrain tem o perfil atual baseado na run dedicada {_safe_text(learned_from.get('dedicated_run_uid'))}, "
                "mas ainda não há um perfil dedicado anterior equivalente. Esta run é baseline pré-mudança local (NAT reduzido e IPv6 habilitado) para comparações futuras."
            )
        else:
            answer = (
                f"{common_answer} Existe baseline anterior dedicada e a comparação temporal está disponível. "
                f"Estado da comparação: {_safe_text(temporal_comparison.get('status'), 'unknown')}."
            )
    elif subtype == "cloudflare_route_baseline_status":
        if temporal_comparison.get("baseline_availability", {}).get("status") == "missing":
            answer = (
                "Não dá para afirmar mudança temporal ainda. "
                f"O RouteBrain tem o perfil atual baseado na run dedicada {_safe_text(learned_from.get('dedicated_run_uid'))}, "
                "mas ainda não há um perfil dedicado anterior equivalente. Esta run é baseline pré-mudança local (NAT reduzido e IPv6 habilitado) para comparações futuras."
            )
        else:
            answer = (
                f"{common_answer} Já existe baseline anterior dedicada e a comparação temporal está disponível. "
                f"Baseline: {_safe_text(temporal_comparison.get('baseline_availability', {}).get('status'))}."
            )
    elif subtype == "cloudflare_route_limitations":
        answer = (
            f"{common_answer} O perfil é parcial e mantém limitações reais: {', '.join(limitations) if limitations else 'sem limitações explícitas'}."
            " A resposta continua read-only e não executa medição."
        )
    elif subtype == "cloudflare_route_asn_gaps":
        answer = (
            f"{common_answer} Nenhum hop tem ASN confirmado no perfil atual. "
            f"Existem {_safe_text(asn_status.get('private_ip_hops'), '0')} hops privados, {_safe_text(asn_status.get('icmp_silent_hops') or route_summary.get('silent_hop_count'), '0')} hops silenciosos e {_safe_text(asn_status.get('hops_without_asn'), '0')} hops públicos sem ASN."
            " Esses campos ficam marcados para o futuro motor de atribuição ASN por correlação."
        )
    elif subtype == "cloudflare_google_common_trunk":
        answer = (
            f"{common_answer} O perfil detecta tronco comum com Google, mas branch_point ainda está {_safe_text(route_summary.get('branch_point'), 'to_be_verified')}."
            " Isso continua sendo evidência operacional, não certeza absoluta de topologia."
        )
    elif subtype == "cloudflare_route_staleness":
        reuse_policy = route_profile_summary.get("reuse_policy") if isinstance(route_profile_summary.get("reuse_policy"), dict) else {}
        answer = (
            f"{common_answer} O perfil é reutilizável, com stale_after_hours={_safe_text(reuse_policy.get('stale_after_hours'), '72')}."
            " Ele deve ser refreshed quando houver nova run dedicada, mudança de rota ou atualização do futuro motor ASN."
        )
    else:
        answer = (
            f"{common_answer} O perfil é parcial: há evidência dedicada, mas o destino final não foi afirmado como certeza e ainda existem lacunas de ASN, reverse DNS, hops silenciosos e IPs privados."
            " O perfil pode ser reutilizado para perguntas atuais sobre Cloudflare, mas não responde posse ASN de todos os hops."
        )

    evidence = [
        f"dedicated_run_uid={learned_from.get('dedicated_run_uid') or '-'}",
        f"logical_hop_count={route_summary.get('logical_hop_count') or route_summary.get('hop_count')}",
        f"responding_hop_count={route_summary.get('responding_hop_count') or asn_status.get('responding_hop_count')}",
        f"silent_hop_count={route_summary.get('silent_hop_count') or asn_status.get('silent_hop_count')}",
        f"edge_count={route_summary.get('edge_count')}",
        f"common_trunk_with_google={route_summary.get('common_trunk_with_google')}",
        f"asn_attribution_status={asn_status.get('attribution_engine_status')}",
    ]
    if route_summary.get("final_destination_asserted") is False:
        evidence.append("final_destination_asserted=false")
    measurement_context = route_profile_summary.get("measurement_context") if isinstance(route_profile_summary.get("measurement_context"), dict) else {}
    if measurement_context:
        evidence.append(f"measurement_context_status={measurement_context.get('measurement_context_status') or 'unknown'}")

    suggested_next_steps = [
        "consultar /route-learning/sessions/demo/cloudflare/route-profile",
        "consultar /route-learning/sessions/demo/cloudflare/visual",
        "consultar /route-learning/sessions/demo/cloudflare/temporal-comparison",
        "aguardar motor futuro de atribuição ASN por correlação para hops privados e sem ASN",
    ]
    if subtype == "cloudflare_google_common_trunk":
        suggested_next_steps.insert(0, "comparar com o perfil Google/8.8.8.8 já persistido")

    limitations_payload = list(limitations) if isinstance(limitations, list) else []
    remaining_ignorance = profile.get("remaining_ignorance") or []
    if not isinstance(remaining_ignorance, list):
        remaining_ignorance = []

    return {
        "intent": "route_profile_query",
        "route_profile_intent": subtype,
        "service": ROUTE_PROFILE_SERVICE,
        "target": ROUTE_PROFILE_TARGET,
        "answer": answer,
        "evidence": evidence,
        "confidence": route_summary.get("confidence") or profile.get("confidence") or "partial",
        "limitations": limitations_payload,
        "remaining_ignorance": remaining_ignorance,
        "suggested_next_steps": suggested_next_steps,
        "active_action_executed": False,
        "source_endpoints": route_profile_summary["source_endpoints"],
        "route_profile_summary": route_profile_summary,
        "route_profile": profile,
        "measurement_context": measurement_context or None,
    }


def _compact_debug_context(bundle: dict[str, Any], answer: dict[str, Any], compact: dict[str, Any]) -> dict[str, Any]:
    request = bundle.get("request") or {}
    raw_context = _safe_request_raw_context(request)
    return {
        "semantic_context": compact.get("semantic_context"),
        "gaps": compact.get("gaps") or [],
        "evidence_summary": compact.get("evidence_summary") or [],
        "classifications": answer.get("classifications") or [],
        "raw_context": raw_context,
    }


def _collect_resolved_ips(bundle: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    resolved: list[str] = []
    for item in bundle.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        if item.get("evidence_type") not in {"dns_resolution", "linked_prior_evidence"}:
            continue
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        for ip_value in (data.get("resolved_ips") or []):
            ip_text = str(ip_value).strip()
            if ip_text and ip_text not in seen:
                seen.add(ip_text)
                resolved.append(ip_text)
    return resolved


def _elapsed_seconds(started_at: Any, finished_at: Any, created_at: Any, updated_at: Any) -> float:
    start = started_at or created_at
    end = finished_at or updated_at
    if hasattr(start, "timestamp") and hasattr(end, "timestamp"):
        return round(max(0.0, float(end.timestamp()) - float(start.timestamp())), 3)
    return 0.0


def _top_semantic_context(semantic_context: dict[str, Any] | None, *, limit: int = 3) -> dict[str, Any]:
    if not isinstance(semantic_context, dict):
        return {
            "search_mode": None,
            "confidence": "suggested",
            "results": [],
        }
    results: list[dict[str, Any]] = []
    for item in semantic_context.get("results") or []:
        if not isinstance(item, dict):
            continue
        results.append(
            {
                "object_type": item.get("object_type"),
                "object_ref": item.get("object_ref"),
                "title": item.get("title"),
                "confidence": "suggested",
                "search_mode": item.get("search_mode") or semantic_context.get("search_mode"),
            }
        )
        if len(results) >= limit:
            break
    top = results[0] if results else {}
    return {
        "search_mode": semantic_context.get("search_mode"),
        "top_object_type": top.get("object_type"),
        "top_object_ref": top.get("object_ref"),
        "title": top.get("title"),
        "confidence": "suggested",
        "results": results,
        "note": "Contexto semântico é sugestivo; confirmação vem das evidências estruturadas.",
    }


def _compact_gaps(gaps: list[dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for gap in gaps[:limit]:
        metadata = gap.get("metadata") if isinstance(gap.get("metadata"), dict) else {}
        compact.append(
            {
                "type": gap.get("gap_type") or gap.get("type"),
                "status": gap.get("status") or "open",
                "reason": gap.get("description") or metadata.get("semantic_context_reason"),
                "severity": gap.get("severity"),
                "recommended_task_type": gap.get("recommended_task_type"),
            }
        )
    return compact


def _compact_evidence(evidence: list[dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for item in evidence[:limit]:
        compact.append(
            {
                "type": item.get("evidence_type") or item.get("type"),
                "entity_type": item.get("entity_type"),
                "entity_value": item.get("entity_value"),
                "confidence": item.get("confidence"),
                "source": item.get("source"),
                "summary": item.get("summary"),
            }
        )
    return compact


def _task_target(task: dict[str, Any], plan: dict[str, Any]) -> str | None:
    input_data = task.get("input") if isinstance(task.get("input"), dict) else {}
    selected = plan.get("selected_targets") or []
    if selected:
        return ", ".join(str(item.get("ip")) for item in selected if item.get("ip")) or input_data.get("target")
    blocked = plan.get("blocked_targets") or []
    if blocked:
        return ", ".join(str(item.get("ip")) for item in blocked if item.get("ip")) or input_data.get("target")
    return input_data.get("target")


def _memory_active_plan(bundle: dict[str, Any]) -> dict[str, Any]:
    request = bundle.get("request") or {}
    request_uid = str(request.get("request_uid") or "")
    raw_context = request.get("raw_context") if isinstance(request.get("raw_context"), dict) else {}
    memory = raw_context.get("learning_memory") if isinstance(raw_context.get("learning_memory"), dict) else {}
    seen: set[str] = set()
    resolved_ips: list[str] = []
    for item in memory.get("ips") or []:
        if not isinstance(item, dict) or not item.get("ip"):
            continue
        ip_text = str(item.get("ip")).strip()
        if ip_text and ip_text not in seen:
            seen.add(ip_text)
            resolved_ips.append(ip_text)
    selected_targets: list[dict[str, Any]] = []
    blocked_targets: list[dict[str, Any]] = []
    skipped_targets: list[dict[str, Any]] = []
    max_targets = int(ACTIVE_MEASUREMENT_POLICY["max_targets_per_request"])
    for ip_text in resolved_ips:
        try:
            classified = classify_target_ip(ip_text)
        except ValueError:
            blocked_targets.append({"ip": ip_text, "reason": "invalid_ip"})
            continue
        if not classified["allowed"]:
            blocked_targets.append(
                {
                    "ip": classified["ip"],
                    "reason": classified["reason_if_blocked"],
                    "blocked_reasons": classified["blocked_reasons"],
                }
            )
            continue
        if len(selected_targets) >= max_targets:
            skipped_targets.append({"ip": classified["ip"], "reason": "target_limit_reached"})
            continue
        selected_targets.append(classified)
    estimated = min(ACTIVE_MEASUREMENT_POLICY["max_total_runtime_seconds"], max(10, len(selected_targets) * 18))
    return {
        "request_uid": request_uid,
        "selected_targets": selected_targets,
        "blocked_targets": blocked_targets,
        "skipped_targets": skipped_targets,
        "estimated_runtime_seconds": estimated,
    }


def build_active_measurements_compact(bundle: dict[str, Any]) -> dict[str, Any]:
    request = bundle.get("request") or {}
    request_uid = str(request.get("request_uid") or "")
    tasks = [task for task in bundle.get("tasks") or [] if task.get("task_type") in ACTIVE_TASK_TYPES]
    consent_status = str(request.get("consent_status") or "not_required")
    if not tasks:
        return {
            "required": False,
            "consent_status": consent_status,
            "can_approve": False,
            "can_execute": False,
            "tasks": [],
            "warnings": [],
            "estimated_runtime_seconds": 0,
            "blocked_targets": [],
            "skipped_targets": [],
        }

    try:
        plan = build_active_measurement_plan(request_uid)
    except RuntimeError:
        plan = {}
    preview = {}
    if request_uid:
        try:
            preview = preview_active_measurement_targets(request_uid)
        except RuntimeError:
            preview = {}
    if not plan.get("selected_targets") and not plan.get("blocked_targets"):
        plan = _memory_active_plan(bundle)
    selected_targets = plan.get("selected_targets") or []
    blocked_targets = plan.get("blocked_targets") or []
    domain = preview.get("target_domain") if isinstance(preview, dict) else None
    requires_dns_resolution = bool(preview.get("requires_dns_resolution")) if isinstance(preview, dict) else False
    reason_if_blocked_preview = preview.get("reason_if_blocked") if isinstance(preview, dict) else None
    next_safe_step = preview.get("next_safe_step") if isinstance(preview, dict) else None
    task_rows: list[dict[str, Any]] = []
    if requires_dns_resolution:
        task_rows.append(
            {
                "task_uid": f"dns_preview_{request_uid}",
                "type": "dns_resolution",
                "target": domain,
                "status": "pending",
                "allowed": True,
                "reason_if_blocked": None,
                "consent_required": False,
                "safe": True,
            }
        )
    if consent_status == "approved":
        approval_note = "Aprovado. Marque a confirmação e clique em Executar medição ativa."
    else:
        approval_note = None
    for task in tasks:
        status = str(task.get("status") or "planned")
        active_status = "waiting_dns" if requires_dns_resolution and task.get("task_type") in ACTIVE_TASK_TYPES else "pending" if status in {"planned", "waiting_consent"} else status
        allowed = bool(selected_targets) and active_status in {"pending", "running"}
        reason_if_blocked = None
        if requires_dns_resolution and task.get("task_type") in ACTIVE_TASK_TYPES:
            reason_if_blocked = "missing_dns_resolution_for_active_targets"
        elif not selected_targets:
            reason_if_blocked = "no_allowed_targets"
        if blocked_targets and not selected_targets:
            reason_if_blocked = ", ".join(str(item.get("reason") or item.get("reason_if_blocked")) for item in blocked_targets[:3])
        task_rows.append(
            {
                "task_uid": task.get("task_uid"),
                "type": task.get("task_type"),
                "target": domain if requires_dns_resolution else _task_target(task, plan),
                "status": active_status,
                "allowed": allowed,
                "reason_if_blocked": reason_if_blocked,
                "consent_required": bool(task.get("requires_consent", True)),
                "safe": False,
            }
        )
    has_pending = any(item["status"] in {"pending", "running", "waiting_dns"} for item in task_rows)
    can_execute = consent_status == "approved" and has_pending
    return {
        "required": has_pending,
        "consent_status": consent_status,
        "can_approve": consent_status not in {"approved", "not_required"} and has_pending,
        "can_execute": can_execute,
        "tasks": task_rows,
        "approval_note": approval_note,
        "warnings": [
            "Medições ativas podem gerar tráfego de rede e só serão executadas após confirmação explícita."
        ],
        "estimated_runtime_seconds": plan.get("estimated_runtime_seconds") or 0,
        "blocked_targets": blocked_targets,
        "skipped_targets": plan.get("skipped_targets") or [],
        "requires_dns_resolution": requires_dns_resolution,
        "target_domain": domain,
        "reason_if_blocked": reason_if_blocked_preview or ("missing_dns_resolution_for_active_targets" if requires_dns_resolution else None),
        "next_safe_step": next_safe_step or ("dns_resolution" if requires_dns_resolution else None),
    }


def _links(request_uid: str) -> dict[str, str]:
    return {
        "detail": f"/learning/requests/{request_uid}",
        "answer": f"/learning/requests/{request_uid}/answer",
        "full": f"/questions/{request_uid}/full",
    }


def build_compact_question_response(bundle: dict[str, Any]) -> dict[str, Any]:
    request = bundle.get("request") or {}
    request_uid = str(request.get("request_uid") or "")
    answer = bundle.get("answer") or {}
    if not answer and request_uid:
        answer = build_answer(request_uid)
    semantic_context = bundle.get("semantic_context") or answer.get("semantic_context")
    traceroute = get_traceroute_summary_for_learning_request(request_uid) if request_uid else {"available": False}
    entities = bundle.get("entities") or []
    request_for_inference = {**request, "_entities": entities}
    inferred = _infer_operational_target(request_for_inference, semantic_context)
    route_profile_info = _infer_route_profile_intent(str(request.get("question") or ""), inferred)
    route_profile_payload = None
    route_profile_answer = None
    if route_profile_info.get("intent"):
        operator_intent = str(route_profile_info.get("intent") or "route_profile_query")
        inferred = {
            **inferred,
            "service": route_profile_info.get("service"),
            "target_ip": ROUTE_PROFILE_TARGET,
            "target_domain": "cloudflare.com",
            "target_label": "Cloudflare route profile",
            "route_profile_intent": route_profile_info.get("subtype"),
        }
        route_profile_payload = build_route_profile(str(route_profile_info.get("service") or ROUTE_PROFILE_SERVICE), str(route_profile_info.get("target") or ROUTE_PROFILE_TARGET))
        route_profile_answer = answer_route_profile_question(str(request.get("question") or ""), route_profile_payload, route_profile_info)
        bgp_visibility_info = {"intent": None}
        asn_route_info = {"intent": None, "asn": None}
    else:
        external_route_intent, external_route_context = _infer_external_route_intent(str(request.get("question") or ""), inferred)
        if external_route_intent:
            operator_intent = external_route_intent
            inferred = {
                **inferred,
                **external_route_context,
                "external_route_intent": external_route_intent,
            }
        else:
            asn_route_info = _infer_asn_route_target(str(request.get("question") or ""), request_for_inference, inferred)
            if asn_route_info.get("asn") is not None:
                explicit_domain_in_question = bool(re.search(r"\b[a-z0-9-]+\.[a-z]{2,}\b", str(request.get("question") or "").lower()))
                inferred = {
                    **inferred,
                    "asn": asn_route_info.get("asn"),
                    "asn_label": asn_route_info.get("label"),
                    "asn_route_intent": asn_route_info.get("intent"),
                    "asn_route_route_change_query": asn_route_info.get("route_change_query"),
                    "target_domain": inferred.get("target_domain") if explicit_domain_in_question else None,
                    "target_label": inferred.get("target_label") if explicit_domain_in_question else None,
                }
            operator_intent = _infer_operator_intent(str(request.get("question") or ""), inferred)
            bgp_visibility_info = _infer_bgp_visibility_target(str(request.get("question") or ""), request_for_inference)
            if bgp_visibility_info.get("intent"):
                operator_intent = bgp_visibility_info.get("intent")
                inferred = {
                    **inferred,
                    "asn": bgp_visibility_info.get("asn"),
                    "target_ip": bgp_visibility_info.get("target_ip"),
                    "target_prefix": bgp_visibility_info.get("target_prefix"),
                    "target_kind": bgp_visibility_info.get("target_kind"),
                }
            if asn_route_info.get("intent") and not bgp_visibility_info.get("intent"):
                operator_intent = asn_route_info.get("intent")
        if external_route_intent:
            bgp_visibility_info = {"intent": None}
            asn_route_info = {"intent": None, "asn": None}
            operator_intent = external_route_intent
        else:
            if "bgp_visibility_info" not in locals():
                bgp_visibility_info = _infer_bgp_visibility_target(str(request.get("question") or ""), request_for_inference)
            if "asn_route_info" not in locals():
                asn_route_info = _infer_asn_route_target(str(request.get("question") or ""), request_for_inference, inferred)
    active = build_active_measurements_compact(bundle)
    if route_profile_payload is not None:
        active = {
            "required": False,
            "consent_status": str(request.get("consent_status") or "not_required"),
            "can_approve": False,
            "can_execute": False,
            "tasks": [],
            "warnings": [],
            "estimated_runtime_seconds": 0,
            "blocked_targets": [],
            "skipped_targets": [],
            "requires_dns_resolution": False,
            "target_domain": None,
            "reason_if_blocked": None,
            "next_safe_step": None,
        }
    if route_profile_answer is not None:
        operational_answer = str(route_profile_answer.get("answer") or operational_answer)
        recommended_actions = []
        active = {
            "required": False,
            "consent_status": "not_required",
            "can_approve": False,
            "can_execute": False,
            "tasks": [],
            "warnings": [],
            "estimated_runtime_seconds": 0,
            "blocked_targets": [],
            "skipped_targets": [],
            "requires_dns_resolution": False,
            "target_domain": None,
            "reason_if_blocked": None,
            "next_safe_step": None,
        }
        bgp_visibility = None
        ip_operational = None
        asn_monitoring = None
        asn_route_change = None
        traceroute = {"available": False, "reason": "route_profile_read_only"}
    resolved_ips = _collect_resolved_ips(bundle)
    operational_answer = _build_operational_answer(request_for_inference, inferred, answer, active, traceroute, semantic_context, bundle.get("gaps") or [], resolved_ips)
    if route_profile_answer is not None:
        operational_answer = str(route_profile_answer.get("answer") or operational_answer)
    recommended_actions = _action_templates(inferred, active, _question_kind_from_intent(request_for_inference, operator_intent))
    if route_profile_answer is not None:
        recommended_actions = []
    bgp_visibility = None
    ip_operational = None
    if route_profile_answer is None and (operator_intent == "ip_operational_check" or (inferred.get("target_ip") and not inferred.get("asn"))):
        try:
            ip_operational = build_ip_operational_answer(str(inferred.get("target_ip") or ""))
        except Exception as exc:
            ip_operational = {"status": "error", "detail": str(exc)}
        if isinstance(ip_operational, dict):
            operational_answer = str(ip_operational.get("operational_answer") or operational_answer)
            recommended_actions = ip_operational.get("recommended_actions") or recommended_actions
    if route_profile_answer is None and bgp_visibility_info.get("intent"):
        try:
            bgp_visibility_answer = build_asn_ip_visibility_answer(int(bgp_visibility_info["asn"]), str(bgp_visibility_info.get("target_ip") or bgp_visibility_info.get("target_prefix") or ""))
        except Exception:
            bgp_visibility_answer = None
        if isinstance(bgp_visibility_answer, dict):
            operational_answer = str(bgp_visibility_answer.get("operational_answer") or operational_answer)
            recommended_actions = bgp_visibility_answer.get("recommended_actions") or recommended_actions
            bgp_visibility = bgp_visibility_answer.get("bgp_visibility")
    asn_monitoring = None
    if asn_route_info.get("asn") is not None and not bgp_visibility_info.get("intent"):
        try:
            asn_monitoring = get_asn_baseline_summary(int(asn_route_info["asn"]))
        except Exception:
            asn_monitoring = None
    if asn_monitoring is not None and not bgp_visibility_info.get("intent"):
        try:
            asn_answer = build_asn_route_change_answer(int(asn_route_info["asn"]), str(request.get("question") or ""), request_uid=request_uid)
        except Exception:
            asn_answer = None
        if isinstance(asn_answer, dict):
            operational_answer = str(asn_answer.get("operational_answer") or operational_answer)
            recommended_actions = asn_answer.get("recommended_actions") or recommended_actions
            inferred = {
                **inferred,
                "asn_route_intent": asn_answer.get("route_change_analysis_status") and asn_route_info.get("intent"),
            }
            asn_route_change = asn_answer.get("asn_route_change")
        else:
            asn_route_change = None
    else:
        asn_route_change = None
    if asn_route_info.get("intent"):
        explicit_domain_in_question = bool(re.search(r"\b[a-z0-9-]+\.[a-z]{2,}\b", str(request.get("question") or "").lower()))
        target_context = {
            **inferred,
            "target_domain": inferred.get("target_domain") if explicit_domain_in_question else None,
            "target_label": inferred.get("target_label") if explicit_domain_in_question else None,
        }
    else:
        target_context = inferred
    response_type = "local_operational" if (operator_intent or request.get("intent")) else "local_utility"
    compact = {
        "request_uid": request_uid,
        "question": request.get("question"),
        "intent": operator_intent or request.get("intent"),
        "status": request.get("status"),
        "consent_status": request.get("consent_status"),
        "answer": operational_answer,
        "operational_answer": operational_answer,
        "active_action_executed": False,
        "semantic_context": _top_semantic_context(semantic_context),
        "gaps": [] if route_profile_answer is not None else _compact_gaps(bundle.get("gaps") or []),
        "evidence_summary": _compact_evidence(bundle.get("evidence") or []),
        "traceroute": traceroute,
        "active_measurements": active,
        "recommended_actions": recommended_actions,
        "target_context": target_context,
        "route_profile_query": route_profile_info if route_profile_answer is not None else None,
        "route_profile_intent": route_profile_answer.get("route_profile_intent") if isinstance(route_profile_answer, dict) else None,
        "route_profile_summary": route_profile_answer.get("route_profile_summary") if isinstance(route_profile_answer, dict) else None,
        "route_profile": route_profile_answer.get("route_profile") if isinstance(route_profile_answer, dict) else None,
        "source_endpoints": route_profile_answer.get("source_endpoints") if isinstance(route_profile_answer, dict) else [],
        "limitations": route_profile_answer.get("limitations") if isinstance(route_profile_answer, dict) else [],
        "remaining_ignorance": route_profile_answer.get("remaining_ignorance") if isinstance(route_profile_answer, dict) else [],
        "asn_monitoring": asn_monitoring,
        "asn_route_change": asn_route_change,
        "bgp_visibility": bgp_visibility,
        "ip_operational": None if route_profile_answer is not None else (ip_operational or (answer.get("ip_operational") if isinstance(answer.get("ip_operational"), dict) else None)),
        "operational_intent": operator_intent,
        "agent_observability": _local_agent_observability(response_type),
        "action_plan": None,
        "debug_context": _compact_debug_context(bundle, answer, {
            "semantic_context": _top_semantic_context(semantic_context),
            "gaps": _compact_gaps(bundle.get("gaps") or []),
            "evidence_summary": _compact_evidence(bundle.get("evidence") or []),
            "asn_monitoring": asn_monitoring,
            "bgp_visibility": bgp_visibility,
            "ip_operational": ip_operational,
        }),
        "warnings": [
            "Autenticação será necessária antes de expor esta UI/API em rede externa.",
        ],
        "elapsed_seconds": _elapsed_seconds(
            request.get("started_at"),
            request.get("finished_at"),
            request.get("created_at"),
            request.get("updated_at"),
        ),
        "links": _links(request_uid),
    }
    compact["action_plan"] = None if route_profile_answer is not None else build_action_plan_for_question(compact)
    return compact


def ask_question_compact(question: str, *, operator: str | None = None) -> dict[str, Any]:
    started = datetime.now().timestamp()
    if should_use_llm_assistant(question):
        compact = _build_conversational_question_response(question)
        compact["elapsed_seconds"] = round(max(0.0, datetime.now().timestamp() - started), 3)
        return compact
    debug_timing: dict[str, float] = {}
    created = create_learning_request(
        question,
        operator=operator,
        raw_context={"source": "questions_api", "dry_run": True},
        debug_timing=debug_timing,
    )
    request_uid = (created.get("request") or {}).get("request_uid") or created.get("request_uid")
    if not request_uid:
        raise RuntimeError("Learning request criada sem UID.")
    bundle = get_learning_request(str(request_uid))
    if bundle is None:
        raise RuntimeError("Learning request criada não foi encontrada.")
    compact = build_compact_question_response(bundle)
    compact["elapsed_seconds"] = round(max(0.0, datetime.now().timestamp() - started), 3)
    compact["timing"] = {
        key: round(float(value), 3)
        for key, value in debug_timing.items()
        if key in {"total_seconds", "semantic_search_total_seconds", "semantic_context_lookup_seconds"}
    }
    return compact


def get_question_compact(request_uid: str) -> dict[str, Any] | None:
    bundle = get_learning_request(request_uid)
    if bundle is None:
        return None
    return build_compact_question_response(bundle)


def get_question_action_plan(request_uid: str) -> dict[str, Any] | None:
    compact = get_question_compact(request_uid)
    if compact is None:
        return None
    action_plan = compact.get("action_plan")
    if isinstance(action_plan, dict):
        return action_plan
    return build_action_plan_for_question(compact)


def get_question_active_plan(request_uid: str) -> dict[str, Any] | None:
    bundle = get_learning_request(request_uid)
    if bundle is None:
        return None
    return build_active_measurements_compact(bundle)


def approve_question_active(request_uid: str) -> dict[str, Any] | None:
    approved = approve_learning_request(request_uid)
    if approved is None:
        return None
    compact = build_compact_question_response(approved)
    active = compact.get("active_measurements") or {}
    active["approval_note"] = "Medições ativas aprovadas. A execução ainda exige chamada separada com confirmação explícita."
    compact["active_measurements"] = active
    return compact


def execute_question_active(request_uid: str, *, confirm: bool) -> dict[str, Any] | None:
    if not confirm:
        raise ValueError("Confirmação explícita obrigatória: envie {\"confirm\": true}.")
    bundle = get_learning_request(request_uid)
    if bundle is None:
        return None
    consent_status = str((bundle.get("request") or {}).get("consent_status") or "")
    if consent_status != "approved":
        raise PermissionError("Medições ativas exigem aprovação antes da execução.")
    dns_preview = resolve_active_targets_for_request(request_uid, force_refresh=True)
    resolved_ips = dns_preview.get("resolved_ips") or []
    if not resolved_ips:
        raise ValueError("Não foi possível executar medição ativa porque nenhum IP público permitido foi encontrado para o domínio.")
    execution = execute_learning_request(
        request_uid,
        dry_run=False,
        allow_safe_tasks=True,
        allow_active_measurements=True,
        force_refresh=False,
    )
    updated = get_learning_request(request_uid)
    if updated is None:
        raise RuntimeError("Request executada, mas não foi possível recarregar a visão compacta.")
    compact = build_compact_question_response(updated)
    compact["execution"] = {
        "status": execution.get("status"),
        "active_measurements_performed": bool((execution.get("execution") or {}).get("active_measurements_performed")),
        "deferred_active_tasks": (execution.get("execution") or {}).get("deferred_active_tasks") or [],
        "blocked_targets": ((execution.get("execution") or {}).get("active_measurements") or {}).get("blocked") or [],
    }
    return compact


def execute_question_action(
    request_uid: str,
    action_id: str,
    *,
    confirm: bool,
    target_override: str | None = None,
    asn: int | None = None,
    label: str | None = None,
    max_duration_seconds: int | None = None,
) -> dict[str, Any] | None:
    if action_id not in ACTION_IDS:
        raise ValueError("Ação desconhecida.")
    bundle = get_learning_request(request_uid)
    if bundle is None:
        return None
    request = bundle.get("request") or {}
    request_for_inference = {**request, "_entities": bundle.get("entities") or []}
    inferred = _infer_operational_target(request_for_inference, bundle.get("semantic_context"))
    asn_route_info = _infer_asn_route_target(str(request.get("question") or ""), request_for_inference, inferred)
    if asn is None and asn_route_info.get("asn") is not None:
        asn = int(asn_route_info["asn"])
    target_domain = str(target_override or inferred.get("target_domain") or "").strip().lower()
    if action_id != "generate_destination_report" and not target_domain and not inferred.get("target_ip"):
        if action_id not in {"add_asn_to_monitoring", "generate_current_asn_snapshot", "show_current_asn_routes", "create_asn_route_report"}:
            raise ValueError("Não há domínio/IP confirmado. Informe target_override, exemplo facebook.com.")

    if action_id == "resolve_dns":
        if not target_domain:
            raise ValueError("Não há domínio/IP confirmado. Informe target_override, exemplo facebook.com.")
        dns_output = resolve_dns_for_domain(request_uid, target_domain, force_refresh=False)
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": dns_output.get("status"),
            "target_domain": target_domain,
            "dns": dns_output,
        }
        return compact

    if action_id in {"trace_route", "trace_route_with_inventory"}:
        if not confirm:
            raise ValueError("Confirmação explícita obrigatória: envie {\"confirm\": true}.")
        if not target_domain:
            raise ValueError("Não há domínio/IP confirmado. Informe target_override, exemplo facebook.com.")
        dns_output = resolve_dns_for_domain(request_uid, target_domain, force_refresh=True)
        resolved_ips = dns_output.get("resolved_ips") or []
        if not resolved_ips:
            raise ValueError("Não foi possível executar medição ativa porque nenhum IP público permitido foi encontrado para o destino.")
        execution = execute_learning_request(
            request_uid,
            dry_run=False,
            allow_safe_tasks=True,
            allow_active_measurements=True,
            force_refresh=False,
        )
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": execution.get("status"),
            "target_domain": target_domain,
            "dns": dns_output,
            "execution": execution,
            "mode": "with_inventory" if action_id == "trace_route_with_inventory" else "trace_only",
        }
        return compact

    if action_id == "generate_destination_report":
        target_ip = inferred.get("target_ip")
        if not target_ip and target_domain:
            raise ValueError("Relatório operacional de destination requer IP observado; resolva o DNS primeiro ou informe target_override com o IP.")
        if not target_ip:
            raise ValueError("Relatório operacional de destination requer IP observado.")
        report = build_observed_destination_report(str(target_ip))
        if report.get("status") != "ok":
            raise ValueError(str(report.get("detail") or "Falha ao gerar relatório operacional."))
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": "completed",
            "target_ip": target_ip,
            "report": report,
        }
        return compact

    if action_id == "promote_to_baseline":
        target_ip = inferred.get("target_ip")
        if not target_ip:
            raise ValueError("Promover para baseline requer IP confirmado.")
        from app.services.observed_destinations import promote_observed_destination_to_baseline

        if not confirm:
            raise ValueError("Confirmação explícita obrigatória: envie {\"confirm\": true}.")
        result = promote_observed_destination_to_baseline(str(target_ip), confirm=True)
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": "completed",
            "target_ip": target_ip,
            "result": result,
        }
        return compact

    if action_id == "measure_baseline":
        target_ip = inferred.get("target_ip")
        if not target_ip:
            raise ValueError("Medição de baseline requer IP confirmado.")
        if not confirm:
            raise ValueError("Confirmação explícita obrigatória: envie {\"confirm\": true}.")
        from app.services.observed_destination_baselines import execute_baseline_active_measurement

        result = execute_baseline_active_measurement(str(target_ip), confirm=True, include_ping=True, include_traceroute=True)
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": result.get("status") or "completed",
            "target_ip": target_ip,
            "result": result,
        }
        compact["ip_operational"] = build_ip_operational_answer(str(target_ip))
        return compact

    if action_id == "view_traceroute_graph":
        target_ip = inferred.get("target_ip")
        if not target_ip:
            raise ValueError("Ver caminho da rota requer IP confirmado.")
        from app.services.observed_destination_baselines import get_baseline_traceroute_graph

        graph = get_baseline_traceroute_graph(str(target_ip))
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": "completed",
            "target_ip": target_ip,
            "graph": graph,
        }
        return compact

    if action_id == "discover_real_navigation_targets":
        if not confirm:
            raise ValueError("Confirmação explícita obrigatória: envie {\"confirm\": true}.")
        if not target_domain:
            raise ValueError("Não há domínio/IP confirmado. Informe target_override, exemplo facebook.com.")
        if run_synthetic_navigation is None or analyze_synthetic_browser_bgp is None:
            compact = build_compact_question_response(bundle)
            compact["action"] = {
                "id": action_id,
                "status": "planned",
                "target_domain": target_domain,
                "message": "Ação planejada, mas executor de navegação sintética ainda não está conectado a /questions/actions.",
            }
            return compact
        max_duration_seconds = 30
        try:
            raw = run_synthetic_navigation(f"https://{target_domain}", timeout_ms=max_duration_seconds * 1000, headless=True, save_har=True, label=target_domain)
        except Exception as exc:
            compact = build_compact_question_response(bundle)
            compact["action"] = {
                "id": action_id,
                "status": "planned",
                "target_domain": target_domain,
                "message": "Ação planejada, mas executor de navegação sintética ainda não está conectado a /questions/actions.",
                "error": str(exc),
            }
            return compact

        analysis = analyze_synthetic_browser_bgp(
            raw.get("json_path"),
            max_hosts=5,
            max_ips_per_host=2,
            ping_count=3,
            ping_timeout=2,
            traceroute=False,
        )
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": "completed",
            "target_domain": target_domain,
            "navigation": analysis,
        }
        compact["discovered_targets"] = [
            {
                "domain": host.get("hostname"),
                "url_or_host": host.get("hostname"),
                "ip": measurement.get("ip"),
                "type": "unknown",
                "asn": None,
                "organization": None,
                "suggested_next_action": "resolve_dns",
            }
            for host in (analysis.get("hosts") or [])
            for measurement in (host.get("measurements") or [])
            if isinstance(measurement, dict)
        ]
        return compact

    if action_id == "add_asn_to_monitoring":
        if not confirm:
            raise ValueError("Confirmação explícita obrigatória: envie {\"confirm\": true}.")
        if asn is None:
            raise ValueError("Não há ASN confirmado. Informe asn, por exemplo 15169.")
        monitoring = add_asn_monitoring_target(asn, label=label or asn_route_info.get("label"), reason="requested_by_operator", request_uid=request_uid)
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": "completed",
            "asn": asn,
            "monitoring": monitoring,
        }
        compact["asn_monitoring"] = get_asn_baseline_summary(asn)
        return compact

    if action_id == "generate_current_asn_snapshot":
        if not confirm:
            raise ValueError("Confirmação explícita obrigatória: envie {\"confirm\": true}.")
        if asn is None:
            raise ValueError("Não há ASN confirmado. Informe asn, por exemplo 15169.")
        snapshot = record_asn_snapshot(asn, reason="requested_by_operator", request_uid=request_uid)
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": "completed",
            "asn": asn,
            "snapshot": snapshot,
        }
        compact["asn_monitoring"] = get_asn_baseline_summary(asn)
        return compact

    if action_id == "show_current_asn_routes":
        if asn is None:
            raise ValueError("Não há ASN confirmado. Informe asn, por exemplo 15169.")
        monitoring = get_asn_monitoring_status(asn)
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": "completed",
            "asn": asn,
            "monitoring": monitoring,
        }
        compact["asn_monitoring"] = monitoring
        return compact

    if action_id == "create_asn_route_report":
        if asn is None:
            raise ValueError("Não há ASN confirmado. Informe asn, por exemplo 15169.")
        report = build_asn_route_change_answer(asn, str(request.get("question") or ""), request_uid=request_uid)
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": "completed",
            "asn": asn,
            "report": report,
        }
        compact["asn_monitoring"] = get_asn_baseline_summary(asn)
        compact["asn_route_change"] = report.get("asn_route_change")
        compact["operational_answer"] = report.get("operational_answer") or compact.get("operational_answer")
        compact["answer"] = compact["operational_answer"]
        compact["recommended_actions"] = report.get("recommended_actions") or compact.get("recommended_actions")
        compact["analysis"] = report.get("analysis") or compact.get("analysis")
        return compact

    if action_id in {"show_bgp_route_for_ip", "check_asn_in_as_path", "generate_asn_ip_visibility_report"}:
        if asn is None:
            raise ValueError("Não há ASN confirmado. Informe asn, por exemplo 15169.")
        target_value = str(target_override or inferred.get("target_ip") or inferred.get("target_prefix") or "").strip()
        if not target_value:
            raise ValueError("Não há IP/prefixo confirmado. Informe target_override, por exemplo 203.0.113.42.")
        report = build_asn_ip_visibility_answer(asn, target_value)
        updated = get_learning_request(request_uid)
        compact = build_compact_question_response(updated or bundle)
        compact["action"] = {
            "id": action_id,
            "status": "completed",
            "asn": asn,
            "target": target_value,
            "report": report,
        }
        compact["bgp_visibility"] = report.get("bgp_visibility")
        compact["operational_answer"] = report.get("operational_answer") or compact.get("operational_answer")
        compact["answer"] = compact["operational_answer"]
        compact["recommended_actions"] = report.get("recommended_actions") or compact.get("recommended_actions")
        return compact

    return None


def list_recent_questions_compact(limit: int = 20) -> list[dict[str, Any]]:
    rows = list_learning_requests(limit=limit)
    compact_rows: list[dict[str, Any]] = []
    for row in rows:
        request_uid = str(row.get("request_uid") or "")
        semantic_context = None
        bundle = get_learning_request(request_uid) if request_uid else None
        if bundle is not None:
            semantic_context = bundle.get("semantic_context")
        traceroute = get_traceroute_summary_for_learning_request(request_uid) if request_uid else {"available": False}
        compact_rows.append(
            {
                "request_uid": request_uid,
                "question": row.get("question"),
                "intent": row.get("intent"),
                "status": row.get("status"),
                "consent_status": row.get("consent_status"),
                "created_at": row.get("created_at"),
                "semantic_context": _top_semantic_context(semantic_context, limit=1),
                "answer": row.get("answer_summary"),
                "gaps_count": int(row.get("gap_count") or 0),
                "traceroute_available": bool(traceroute.get("available")),
            }
        )
    return compact_rows


def build_speech_text_from_question_response(compact_response: dict[str, Any], mode: str = "answer") -> tuple[str, bool]:
    question = str(compact_response.get("question") or "").strip()
    answer = str(compact_response.get("answer") or "").strip()
    gaps = compact_response.get("gaps") or []
    semantic_context = compact_response.get("semantic_context") or {}
    evidence = compact_response.get("evidence_summary") or []

    parts: list[str] = []
    if question:
        parts.append(f"Pergunta: {question}.")
    if answer:
        parts.append(f"Resposta: {answer}.")

    if mode == "full":
        gap_texts: list[str] = []
        for gap in gaps[:4]:
            if not isinstance(gap, dict):
                continue
            gap_text = gap.get("reason") or gap.get("type")
            if gap_text:
                gap_texts.append(str(gap_text))
        if gap_texts:
            parts.append(f"Lacunas restantes: {', '.join(gap_texts)}.")
        evidence_texts: list[str] = []
        for item in evidence[:3]:
            if not isinstance(item, dict):
                continue
            summary = item.get("summary") or item.get("type")
            if summary:
                evidence_texts.append(str(summary))
        if evidence_texts:
            parts.append(f"Evidências resumidas: {', '.join(evidence_texts)}.")
        if isinstance(semantic_context, dict) and semantic_context.get("note"):
            parts.append(str(semantic_context.get("note")))

    text = " ".join(part.strip() for part in parts if part.strip()).strip()
    truncated = len(text) > 5000
    if truncated:
        text = text[:5000].rstrip()
    return text, truncated
