from __future__ import annotations

import hashlib
import copy
import ipaddress
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from psycopg.rows import dict_row

from app.db.connection import get_connection
from app.services.external_route_inventory import compare_service_routes, get_external_route_trace_graph, get_service_route_summary
from app.services.route_graph import build_service_route_graph
from app.services.route_learning_demo import get_route_learning_demo_payload

_SUPPORTED_TARGET = "8.8.8.8"
_SUPPORTED_SERVICE = "google"
_CLOUDFLARE_TARGET = "cloudflare"
_CLOUDFLARE_SERVICE = "cloudflare"
_CLOUDFLARE_DEDICATED_TRACE_PLAN_UIDS = {
    "plan-cloudflare-dedicated-trace-v1",
    "plan-cloudflare-ipv4-post-nat-ipv6-change-v1",
    "plan-cloudflare-ipv6-post-nat-ipv6-change-v1",
}
_PRINCIPLE = "Não uma máquina estática e sim uma máquina que aprende pela revelação da própria ignorância!"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _confidence_to_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip().lower()
    if text == "confirmed":
        return 0.95
    if text == "probable":
        return 0.75
    if text == "suggested":
        return 0.55
    if text == "unknown":
        return 0.0
    try:
        return float(text)
    except (TypeError, ValueError):
        return 0.0


def _normalize_ip(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _normalize_service(value: str | None) -> str:
    slug = str(value or _SUPPORTED_SERVICE).strip().lower()
    return slug or _SUPPORTED_SERVICE


def _safe_target_label(target: str) -> str:
    normalized = _normalize_ip(target) or str(target).strip()
    return f"Rota para {normalized}"


def _safe_uid_fragment(value: str) -> str:
    return str(value).strip().lower().replace(".", "-").replace("/", "-").replace(" ", "-")


def _is_cloudflare_dedicated_trace_plan(plan_uid: Any) -> bool:
    return str(plan_uid or "").strip() in _CLOUDFLARE_DEDICATED_TRACE_PLAN_UIDS


def _service_graph_node_map(service_graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
    nodes_by_ip: dict[str, dict[str, Any]] = {}
    for node in service_graph.get("nodes", []):
        ip = _normalize_ip(node.get("ip"))
        if ip:
            nodes_by_ip[ip] = node
    return nodes_by_ip


def _trace_nodes_by_hop(trace_graph: dict[str, Any]) -> dict[int, dict[str, Any]]:
    hops: dict[int, dict[str, Any]] = {}
    for node in trace_graph.get("nodes", []):
        hop = int(node.get("hop") or 0)
        if hop > 0:
            hops[hop] = node
    return hops


def _trace_edges_by_hop(trace_graph: dict[str, Any]) -> dict[int, dict[str, Any]]:
    edges: dict[int, dict[str, Any]] = {}
    for edge in trace_graph.get("edges", []):
        hop = int(edge.get("from_hop_index") or 0)
        if hop > 0:
            edges[hop] = edge
    return edges


def _node_state_for_hop(hop: int, ip: str | None) -> tuple[str, str, bool, bool, float, str]:
    mapping: dict[int, tuple[str, str, bool, bool, float, str]] = {
        1: ("known", "known", True, True, 0.98, "Origem local conhecida; ponto de partida do caminho."),
        2: ("known", "known", True, True, 0.96, "Gateway local conhecido no inventário."),
        3: ("icmp_silent_forwarding_ok", "icmp_silent_forwarding_ok", False, True, 0.38, "Hop sem resposta revelou uma lacuna explícita no caminho."),
        4: ("known", "known", True, True, 0.92, "Trecho privado recorrente já conhecido como caminho da operadora."),
        5: ("queued_for_inventory", "queued_for_inventory", False, True, 0.74, "Hop observado agora. Enfileirado para enriquecimento."),
        6: ("known", "known", True, True, 0.90, "Hop privado conhecido reaproveitado do histórico."),
        7: ("queued_for_inventory", "queued_for_inventory", False, True, 0.71, "Hop privado observado. Entrada na fila para classificação histórica."),
        8: ("icmp_silent_forwarding_ok", "icmp_silent_forwarding_ok", False, True, 0.36, "Silêncio ICMP revelou outra lacuna explícita no caminho."),
        9: ("known", "known", True, True, 0.88, "Trecho privado conhecido do histórico consolidado."),
        10: ("enriching", "enriching", True, True, 0.77, "Trecho privado recorrente; enriquecimento em background."),
        11: ("known", "known", True, True, 0.86, "Trecho privado conhecido e reaproveitado."),
        12: ("queued_for_inventory", "queued_for_inventory", False, True, 0.64, "Trecho ainda privado; organização pendente."),
        13: ("learned_now", "learned_now", True, True, 0.93, "Trecho público Google/CDN reconhecido e consolidado nesta leitura."),
        14: ("limited", "limited", False, True, 0.53, "Hop público sem ASN local; enriquecimento fica pendente."),
        15: ("inferred", "inferred", True, True, 0.55, "Intermediário público inferido pela posição."),
        16: ("learned_now", "learned_now", True, True, 0.98, "Destino 8.8.8.8 associado a Google/AS15169 por evidência local."),
    }
    if hop in mapping:
        return mapping[hop]
    return ("limited", "limited", False, True, 0.5, f"Hop {ip or hop} observado com leitura limitada.")


def _cluster_for_node(cluster: str | None, knowledge_state: str, ip: str | None) -> str:
    if not ip:
        return "unknown"
    if knowledge_state == "learned_now" and cluster in {"cdn_cloud", "destination"}:
        return cluster or "unknown"
    return str(cluster or "unknown")


def _role_for_node(role: str | None, knowledge_state: str, ip: str | None) -> str:
    if not ip:
        return "unknown"
    if knowledge_state == "learned_now" and role in {"cdn_edge", "destination"}:
        return role or "unknown"
    return str(role or "unknown")


def _symbol_for_node(cluster: str, knowledge_state: str, ip_type: str) -> dict[str, Any]:
    if cluster == "local":
        return {"device_icon": "RB-ICON-0110", "org_badge": "RB-ORG-0090", "flag": "RB-FLAG-BR", "states": ["RB-STATE-0040"]}
    if cluster == "cpe_onu":
        return {"device_icon": "RB-ICON-0060", "org_badge": "RB-ORG-0090", "flag": "RB-FLAG-BR", "states": ["RB-STATE-0040"]}
    if cluster == "provider_private":
        return {"device_icon": "RB-ICON-0100", "org_badge": "RB-ORG-0090", "flag": "RB-FLAG-BR", "states": ["RB-STATE-0010", "RB-STATE-0040"]}
    if cluster == "cdn_cloud":
        return {"device_icon": "RB-ICON-0120", "org_badge": "RB-ORG-0010", "flag": "RB-FLAG-US", "states": ["RB-STATE-0030", "RB-STATE-0040"]}
    if cluster == "destination":
        return {"device_icon": "RB-ICON-0090", "org_badge": "RB-ORG-0010", "flag": "RB-FLAG-US", "states": ["RB-STATE-0040"]}
    if knowledge_state == "inferred":
        return {"device_icon": "RB-ICON-0010", "org_badge": "RB-ORG-0100", "flag": "RB-FLAG-US", "states": ["RB-STATE-0020", "RB-STATE-0030"]}
    if knowledge_state == "learned_now":
        return {"device_icon": "RB-ICON-0010" if ip_type == "public" else "RB-ICON-0100", "org_badge": "RB-ORG-0010" if ip_type == "public" else "RB-ORG-0090", "flag": "RB-FLAG-US" if ip_type == "public" else "RB-FLAG-BR", "states": ["RB-STATE-0030", "RB-STATE-0040"]}
    if knowledge_state == "queued_for_inventory":
        return {"device_icon": "RB-ICON-0100" if ip_type == "private" else "RB-ICON-0080", "org_badge": "RB-ORG-0090" if ip_type == "private" else "RB-ORG-0100", "flag": "RB-FLAG-BR" if ip_type == "private" else "RB-FLAG-US", "states": ["RB-STATE-0010", "RB-STATE-0030"]}
    if knowledge_state == "enriching":
        return {"device_icon": "RB-ICON-0100", "org_badge": "RB-ORG-0090", "flag": "RB-FLAG-BR", "states": ["RB-STATE-0010"]}
    if knowledge_state in {"limited", "icmp_silent_forwarding_ok"}:
        return {"device_icon": "RB-ICON-0080", "org_badge": "RB-ORG-0100", "flag": "RB-FLAG-US" if ip_type == "public" else "RB-FLAG-UN", "states": ["RB-STATE-0020", "RB-STATE-0030"]}
    return {"device_icon": "RB-ICON-0080", "org_badge": "RB-ORG-0100", "flag": "RB-FLAG-UN", "states": ["RB-STATE-0020"]}


def _queue_status_for_state(knowledge_state: str) -> str | None:
    if knowledge_state == "queued_for_inventory":
        return "queued"
    if knowledge_state == "enriching":
        return "running"
    if knowledge_state in {"limited", "inferred"}:
        return "limited"
    if knowledge_state == "icmp_silent_forwarding_ok":
        return "queued"
    if knowledge_state in {"known", "learned_now"}:
        return "completed"
    return None


def _learning_action_for_state(knowledge_state: str, ip_type: str) -> str:
    if knowledge_state == "queued_for_inventory":
        return "classify_private_path" if ip_type == "private" else "lookup_bgp_local_if_public"
    if knowledge_state == "enriching":
        return "search_historical_observations"
    if knowledge_state in {"limited", "inferred"}:
        return "lookup_reverse_dns_if_public" if ip_type == "public" else "search_historical_observations"
    if knowledge_state == "icmp_silent_forwarding_ok":
        return "queue_inventory"
    return "none"


def _step_evidence_source(hop: int, knowledge_state: str) -> str:
    if hop in {1, 2, 4, 6, 9, 11}:
        return "routegraph/service/google"
    if hop in {13, 14, 15, 16}:
        return "routegraph/global"
    if hop in {3, 8, 5, 7, 10, 12}:
        return "external_route_trace"
    if knowledge_state == "enriching":
        return "routegraph/service/google"
    return "routegraph/global"


def _build_origin_node() -> dict[str, Any]:
    return {
        "id": "origin:local",
        "node_type": "origin",
        "label": "Origem local",
        "short_label": "local",
        "ip": None,
        "cluster": "local",
        "role": "local_gateway",
        "knowledge_state": "known",
        "visual_state": "known",
        "position_hint": {"level": 0, "branch": 0, "order": 0},
        "symbol": {"device_icon": "RB-ICON-0110", "org_badge": "RB-ORG-0090", "flag": "RB-FLAG-BR", "states": ["RB-STATE-0040"]},
        "known_before": True,
        "observed_now": False,
        "confidence": 0.98,
        "operator_message": "Origem local conhecida; ponto de partida do caminho.",
        "metadata": {"demo_mode": True, "demo_visual_anchor": True, "source_refs": ["routegraph/global"]},
    }


def _build_hop_node(
    *,
    hop: int,
    trace_node: dict[str, Any],
    service_node: dict[str, Any] | None,
) -> dict[str, Any]:
    ip = _normalize_ip(trace_node.get("ip"))
    knowledge_state, visual_state, known_before, observed_now, confidence, operator_message = _node_state_for_hop(hop, ip)
    if service_node and ip:
        cluster = _cluster_for_node(str(service_node.get("cluster") or "unknown"), knowledge_state, ip)
        role = _role_for_node(str(service_node.get("role") or "unknown"), knowledge_state, ip)
        category = str(service_node.get("category") or "unknown")
        organization = service_node.get("organization")
        country = service_node.get("country")
        reverse_dns = service_node.get("reverse_dns")
        services_seen = service_node.get("services_seen") or []
        observations_count = int(service_node.get("observations_count") or 0)
        confidence = round(float(service_node.get("confidence") or confidence), 3)
    else:
        cluster = "unknown"
        role = "unknown"
        category = "unknown"
        organization = None
        country = None
        reverse_dns = None
        services_seen = []
        observations_count = 0
    ip_type = "private" if ip and ipaddress.ip_address(ip).is_private else ("public" if ip else "unknown")
    if hop == 13 and service_node:
        # The trace node is public and already persisted, but the session still learns it now.
        knowledge_state = "learned_now"
        visual_state = "learned_now"
        known_before = True
        observed_now = True
        confidence = round(float(service_node.get("confidence") or confidence), 3)
        operator_message = "Trecho público Google/CDN reconhecido e consolidado nesta leitura."
    elif hop == 14:
        knowledge_state = "limited"
        visual_state = "limited"
        known_before = False
        observed_now = True
        operator_message = "Hop público sem ASN local; enriquecimento fica pendente."
    elif hop == 15 and service_node:
        knowledge_state = "inferred"
        visual_state = "inferred"
        known_before = True
        observed_now = True
        operator_message = "Intermediário público inferido pela posição."
    elif hop == 16:
        knowledge_state = "learned_now"
        visual_state = "learned_now"
        known_before = True
        observed_now = True
        operator_message = "Destino 8.8.8.8 associado a Google/AS15169 por evidência local."
    elif hop in {5, 7, 12}:
        known_before = False
        observed_now = True
    elif hop in {3, 8}:
        known_before = False
        observed_now = True
    elif hop == 10:
        knowledge_state = "enriching"
        visual_state = "enriching"
        known_before = True
        observed_now = True
    symbol = _symbol_for_node(cluster, knowledge_state, ip_type)
    return {
        "id": f"hop:{ip}" if ip else f"hop:unknown:{hop}",
        "node_type": "hop",
        "label": ip or "No reply",
        "short_label": ip.split(".")[-2] + "." + ip.split(".")[-1] if ip and ip.count(".") == 3 else (f"ttl {hop}" if not ip else ip.split(".")[-1]),
        "ip": ip,
        "cluster": cluster,
        "role": role,
        "knowledge_state": knowledge_state,
        "visual_state": visual_state,
        "position_hint": {"level": max(hop - 1, 0), "branch": 0, "order": max(hop - 1, 0)},
        "symbol": symbol,
        "known_before": known_before,
        "observed_now": observed_now,
        "confidence": confidence,
        "operator_message": operator_message,
        "metadata": {
            "demo_mode": True,
            "source_refs": [
                "routegraph/service/google" if hop in {1, 2, 4, 5, 6, 7, 9, 10, 11, 12} else "routegraph/global",
                "external_route_trace_execute_inventory:etr-google-fd706b5de68147a0",
            ],
            "trace_hop": hop,
            "observations_count": observations_count,
            "services_seen": services_seen,
            "category": category,
            "organization": organization,
            "country": country,
            "reverse_dns": reverse_dns,
            "demo_visual_anchor": False,
        },
    }


def _build_unknown_hop_node(hop: int, previous_ip: str | None, next_ip: str | None) -> dict[str, Any]:
    return {
        "id": f"hop:unknown:{hop}",
        "node_type": "hop",
        "label": "No reply",
        "short_label": f"ttl {hop}",
        "ip": None,
        "cluster": "unknown",
        "role": "unknown",
        "knowledge_state": "icmp_silent_forwarding_ok",
        "visual_state": "icmp_silent_forwarding_ok",
        "position_hint": {"level": max(hop - 1, 0), "branch": 0, "order": max(hop - 1, 0)},
        "symbol": {"device_icon": "RB-ICON-0080", "org_badge": "RB-ORG-0100", "flag": "RB-FLAG-UN", "states": ["RB-STATE-0020", "RB-STATE-0030"]},
        "known_before": False,
        "observed_now": True,
        "confidence": 0.38,
        "operator_message": "ICMP silencioso revelou uma lacuna explícita no caminho.",
        "metadata": {
            "demo_mode": True,
            "source_refs": ["external_route_trace_execute_inventory:etr-google-fd706b5de68147a0"],
            "trace_hop": hop,
            "gap_previous_hop": previous_ip,
            "gap_next_hop": next_ip,
            "demo_visual_anchor": False,
        },
    }


def _build_edge(
    *,
    edge: dict[str, Any],
    hop: int,
    source_node_id: str,
    target_node_id: str,
) -> dict[str, Any]:
    transition_type = str(edge.get("transition_type") or "unknown_transition")
    if transition_type == "lan_to_cpe":
        visual_state = "known"
        operator_message = "Ligação real entre gateway local e CPE/ONU."
    elif transition_type == "provider_private_to_provider_private":
        visual_state = "observed_now"
        operator_message = "Trecho privado recorrente confirmado no caminho."
    elif transition_type == "provider_private_to_public_edge":
        visual_state = "observed_now"
        operator_message = "Saída para o trecho público observada na sessão."
    elif transition_type == "transit_to_destination":
        visual_state = "learned_now"
        operator_message = "Destino alcançado e reconhecido como Google/8.8.8.8."
    else:
        visual_state = "icmp_silent_forwarding_ok"
        operator_message = "Gap observado na rota; não inventar o hop ausente."
    confidence = edge.get("confidence")
    if isinstance(confidence, str):
        confidence_value = 0.7 if confidence == "suggested" else 0.8 if confidence == "probable" else 0.9 if confidence == "confirmed" else 0.5
    else:
        confidence_value = float(confidence or 0.7)
    return {
        "id": f"edge:{edge.get('edge_uid')}",
        "source": source_node_id,
        "target": target_node_id,
        "edge_type": "route_hop",
        "transition_type": transition_type,
        "observed_now": True,
        "known_before": visual_state in {"known", "learned_now"},
        "visual_state": visual_state,
        "confidence": round(confidence_value, 3),
        "operator_message": operator_message,
        "metadata": {
            "demo_mode": True,
            "trace_hop": hop,
            "demo_visual_anchor": False,
            "source_refs": ["external_route_trace_execute_inventory:etr-google-fd706b5de68147a0"],
        },
    }


def _build_demo_anchor_edge() -> dict[str, Any]:
    return {
        "id": "edge:origin:local->hop:10.20.0.1",
        "source": "origin:local",
        "target": "hop:10.20.0.1",
        "edge_type": "synthetic_dependency",
        "transition_type": "origin_to_local_gateway",
        "observed_now": False,
        "known_before": True,
        "visual_state": "known",
        "confidence": 1.0,
        "operator_message": "Raiz visual do caminho até o gateway local.",
        "metadata": {"demo_mode": True, "demo_visual_anchor": True, "source_refs": ["routegraph/global"]},
    }


def _build_steps(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    hop_nodes = [node for node in nodes if node.get("node_type") == "hop"]
    previous_hop_ip: str | None = None
    for index, node in enumerate(hop_nodes, start=1):
        ip = node.get("ip")
        next_ip = hop_nodes[index].get("ip") if index < len(hop_nodes) else None
        knowledge_state = str(node.get("knowledge_state") or "unknown")
        ip_type = "private" if ip and ipaddress.ip_address(str(ip)).is_private else ("public" if ip else "unknown")
        steps.append(
            {
                "step_uid": f"step-{index:02d}",
                "step_index": index,
                "hop_ip": ip,
                "previous_hop": previous_hop_ip,
                "next_hop": next_ip,
                "known_before": bool(node.get("known_before")),
                "observed_now": bool(node.get("observed_now")),
                "knowledge_state": knowledge_state,
                "evidence_source": _step_evidence_source(index, knowledge_state),
                "learning_action": _learning_action_for_state(knowledge_state, ip_type),
                "queue_status": _queue_status_for_state(knowledge_state),
                "confidence": node.get("confidence"),
                "operator_message": node.get("operator_message"),
                "visual_state": node.get("visual_state"),
            }
        )
        previous_hop_ip = ip
    return steps


def _build_ignorance_events(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    by_hop = {int(node.get("position_hint", {}).get("order", 0)) + 1: node for node in nodes if node.get("node_type") == "hop"}

    gap_hops = [3, 8]
    for index, hop in enumerate(gap_hops, start=1):
        node = by_hop.get(hop)
        next_node = by_hop.get(hop + 1)
        events.append(
            {
                "event_uid": f"ie-{index:02d}",
                "event_type": "icmp_no_reply_but_forwarding_continues",
                "object_type": "hop",
                "object_id": node["id"] if node else f"hop:unknown:{hop}",
                "revealed_by": "route_trace_to_8.8.8.8",
                "evidence": f"Hop {hop} did not reply, but the path continued to {next_node.get('ip') if next_node else 'unknown'}.",
                "priority": "high",
                "next_action": "queue_inventory",
                "requires_active_action": False,
                "can_learn_in_background": True,
                "operator_message": "Hop sem resposta revelou uma lacuna explícita no caminho.",
            }
        )
    private_hop = by_hop.get(5)
    if private_hop:
        events.append(
            {
                "event_uid": "ie-03",
                "event_type": "private_hop_no_public_rdap",
                "object_type": "hop",
                "object_id": private_hop["id"],
                "revealed_by": "route_trace_to_8.8.8.8",
                "evidence": "Private hop observed in route with no public RDAP match.",
                "priority": "normal",
                "next_action": "classify_private_path",
                "requires_active_action": False,
                "can_learn_in_background": True,
                "operator_message": "Hop privado observado em rota real e enviado para enriquecimento.",
            }
        )
    role_gap_hop = by_hop.get(7)
    if role_gap_hop:
        events.append(
            {
                "event_uid": "ie-04",
                "event_type": "missing_role_classification",
                "object_type": "hop",
                "object_id": role_gap_hop["id"],
                "revealed_by": "route_trace_to_8.8.8.8",
                "evidence": "Private hop is visible in the path but still lacks a strong operational role.",
                "priority": "normal",
                "next_action": "search_historical_observations",
                "requires_active_action": False,
                "can_learn_in_background": True,
                "operator_message": "Ainda não sei o papel preciso deste hop; a fila vai buscar contexto.",
            }
        )
    public_asn_gap = by_hop.get(13)
    if public_asn_gap:
        events.append(
            {
                "event_uid": "ie-05",
                "event_type": "missing_asn",
                "object_type": "hop",
                "object_id": public_asn_gap["id"],
                "revealed_by": "route_trace_to_8.8.8.8",
                "evidence": "Public hop seen in the path without a local ASN match.",
                "priority": "normal",
                "next_action": "lookup_bgp_local_if_public",
                "requires_active_action": False,
                "can_learn_in_background": True,
                "operator_message": "Hop público sem ASN local; enriquecer em background.",
            }
        )
    public_rdns_gap = by_hop.get(15)
    if public_rdns_gap:
        events.append(
            {
                "event_uid": "ie-06",
                "event_type": "missing_reverse_dns",
                "object_type": "hop",
                "object_id": public_rdns_gap["id"],
                "revealed_by": "route_trace_to_8.8.8.8",
                "evidence": "Transit hop reached the destination with no reverse DNS in the local view.",
                "priority": "low",
                "next_action": "lookup_reverse_dns_if_public",
                "requires_active_action": False,
                "can_learn_in_background": True,
                "operator_message": "Falta reverse DNS para fechar a leitura deste trecho.",
            }
        )
    return events


def _build_learning_queue(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    queue: list[dict[str, Any]] = []
    by_ip = {node.get("ip"): node for node in nodes if node.get("ip")}
    private_candidates = [by_ip.get("10.22.0.18"), by_ip.get("10.22.0.17")]
    for index, node in enumerate([item for item in private_candidates if item], start=1):
        queue.append(
            {
                "queue_uid": f"lq-{index:02d}",
                "object_type": "hop",
                "object_id": node["id"],
                "reason": "observed_in_real_route" if index == 1 else "recurring_private_hop",
                "priority_score": 88 if index == 1 else 72,
                "priority_reasons": ["observed_in_real_route", "provider_private_path"] if index == 1 else ["recurring_private_hop", "provider_private_path"],
                "status": "queued" if index == 1 else "running",
                "planned_actions": ["classify_private_path", "search_historical_observations"],
                "requires_consent": False,
                "operator_message": "Inventário/enriquecimento agendado por uso real." if index == 1 else "Hop privado recorrente em tratamento.",
            }
        )
    public_candidate = by_ip.get("203.0.113.72")
    if public_candidate:
        queue.append(
            {
                "queue_uid": "lq-03",
                "object_type": "hop",
                "object_id": public_candidate["id"],
                "reason": "public_hop_without_asn_org",
                "priority_score": 61,
                "priority_reasons": ["public_hop_without_asn_org", "near_cdn_or_edge"],
                "status": "queued",
                "planned_actions": ["lookup_bgp_local_if_public", "lookup_reverse_dns_if_public", "enrich_public_asn_if_allowed"],
                "requires_consent": False,
                "operator_message": "Hop público sem ASN/org local; enriquecimento futuro em background.",
            }
        )
    transit_candidate = by_ip.get("198.51.100.77")
    if transit_candidate:
        queue.append(
            {
                "queue_uid": "lq-04",
                "object_type": "hop",
                "object_id": transit_candidate["id"],
                "reason": "transit_needs_context",
                "priority_score": 48,
                "priority_reasons": ["transit_needs_context", "destination_path"],
                "status": "limited",
                "planned_actions": ["lookup_reverse_dns_if_public", "enrich_public_asn_if_allowed"],
                "requires_consent": False,
                "operator_message": "Trecho de trânsito com contexto parcial; aprendizagem limitada.",
            }
        )
    return queue


def _build_tree(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    hop_nodes = [node for node in nodes if node.get("node_type") == "hop"]
    path_node_sequence = ["origin:local", *[node["id"] for node in hop_nodes]]
    path_edge_sequence = [edge["id"] for edge in edges if edge["id"].startswith("edge:edge-etr-google") or edge["id"] == "edge:origin:local->hop:10.20.0.1"]
    return {
        "tree_uid": "tree-demo-8-8-8-8-builder",
        "root_node_id": "origin:local",
        "paths": [
            {
                "path_uid": "path-demo-8-8-8-8-builder",
                "target": _SUPPORTED_TARGET,
                "node_sequence": path_node_sequence,
                "edge_sequence": path_edge_sequence,
                "created_from": "existing_routegraph_and_external_route_inventory",
                "is_baseline": True,
            }
        ],
        "branches": [],
        "common_trunks": [
            {
                "trunk_uid": "trunk-local-provider",
                "node_sequence": ["origin:local", "hop:10.20.0.1", "hop:10.21.0.1", "hop:unknown:3", "hop:10.22.0.14", "hop:10.22.0.18", "hop:10.22.0.19", "hop:10.22.0.17"],
                "description": "Tronco local + provider_private reutilizável em rotas relacionadas.",
            }
        ],
    }


def _build_timeline(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], steps: list[dict[str, Any]], ignorance_events: list[dict[str, Any]], learning_queue: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    time_index = 1
    timeline.append(
        {
            "time_index": time_index,
            "event_type": "session_started",
            "target_id": "session:demo-route-learning-8-8-8-8-builder",
            "message": "Sessão builder iniciada para 8.8.8.8.",
            "visual_effect": "pulse",
            "duration_ms": 700,
        }
    )
    time_index += 1
    timeline.append(
        {
            "time_index": time_index,
            "event_type": "node_added",
            "target_id": "origin:local",
            "message": "Origem local colocada no canvas.",
            "visual_effect": "draw_node",
            "duration_ms": 500,
        }
    )
    time_index += 1

    hop_nodes = [node for node in nodes if node.get("node_type") == "hop"]
    edge_by_source = {edge["source"]: edge for edge in edges if edge.get("source")}
    for node in hop_nodes:
        timeline.append(
            {
                "time_index": time_index,
                "event_type": "node_added",
                "target_id": node["id"],
                "message": f"Nó observado: {node['label']}.",
                "visual_effect": "draw_node",
                "duration_ms": 500,
            }
        )
        time_index += 1
        edge = edge_by_source.get(node["id"])
        if edge:
            timeline.append(
                {
                    "time_index": time_index,
                    "event_type": "edge_added",
                    "target_id": edge["id"],
                    "message": f"Edge observada entre {edge['source']} e {edge['target']}.",
                    "visual_effect": "draw_edge",
                    "duration_ms": 500,
                }
            )
            time_index += 1
        timeline.append(
            {
                "time_index": time_index,
                "event_type": "packet_moved",
                "target_id": node["id"],
                "message": f"Pacote avança para {node['label']}.",
                "visual_effect": "move_packet",
                "duration_ms": 650,
            }
        )
        time_index += 1
        if node.get("knowledge_state") in {"icmp_silent_forwarding_ok", "queued_for_inventory", "enriching", "limited", "inferred"}:
            timeline.append(
                {
                    "time_index": time_index,
                    "event_type": "knowledge_checked",
                    "target_id": node["id"],
                    "message": f"Cheque de conhecimento para {node['label']}.",
                    "visual_effect": "spinner",
                    "duration_ms": 650,
                }
            )
            time_index += 1
        if node.get("knowledge_state") in {"icmp_silent_forwarding_ok", "queued_for_inventory", "limited", "inferred"}:
            timeline.append(
                {
                    "time_index": time_index,
                    "event_type": "ignorance_revealed",
                    "target_id": node["id"],
                    "message": node.get("operator_message"),
                    "visual_effect": "highlight_branch",
                    "duration_ms": 800,
                }
            )
            time_index += 1
        if node.get("knowledge_state") in {"queued_for_inventory", "enriching", "limited"}:
            timeline.append(
                {
                    "time_index": time_index,
                    "event_type": "queued_for_learning",
                    "target_id": node["id"],
                    "message": f"{node['label']} enfileirado para aprendizagem.",
                    "visual_effect": "badge_update",
                    "duration_ms": 750,
                }
            )
            time_index += 1

    timeline.append(
        {
            "time_index": time_index,
            "event_type": "session_completed",
            "target_id": "session:demo-route-learning-8-8-8-8-builder",
            "message": "Sessão builder finalizada com lacunas ainda visíveis.",
            "visual_effect": "pulse",
            "duration_ms": 700,
        }
    )
    return timeline


def _summary_for_nodes(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    hop_nodes = [node for node in nodes if node.get("node_type") == "hop"]
    counts = Counter(str(node.get("knowledge_state") or "unknown") for node in hop_nodes)
    observed_now_count = sum(1 for node in hop_nodes if node.get("observed_now") and not node.get("known_before"))
    return {
        "total_steps": len(hop_nodes),
        "known_count": counts.get("known", 0),
        "observed_now_count": observed_now_count,
        "unknown_count": counts.get("unknown", 0) + counts.get("icmp_silent_forwarding_ok", 0),
        "queued_count": counts.get("queued_for_inventory", 0),
        "enriching_count": counts.get("enriching", 0),
        "learned_now_count": counts.get("learned_now", 0),
        "limited_count": counts.get("limited", 0) + counts.get("inferred", 0),
        "suspected_failure_count": counts.get("suspected_failure", 0),
        "icmp_silent_forwarding_ok_count": counts.get("icmp_silent_forwarding_ok", 0),
        "branch_count": 0,
        "evidence_sources": [
            "routegraph/global",
            "routegraph/service/google",
            "external_route_trace_execute_inventory:etr-google-fd706b5de68147a0",
            "routegraph_v1_backend",
        ],
        "active_action_executed": False,
        "requires_consent_for_active_actions": False,
    }


def _build_shared_cloudflare_node(row: dict[str, Any], order: int) -> dict[str, Any]:
    ip = _normalize_ip(row.get("hop_ip"))
    ip_type = "private" if ip and ipaddress.ip_address(ip).is_private else ("public" if ip else "unknown")
    confidence = 0.7
    if str(row.get("confidence") or "") == "confirmed":
        confidence = 0.78
    role = str(row.get("role") or "unknown")
    knowledge_state = "queued_for_inventory" if role in {"unknown", "local_or_private"} else "known"
    visual_state = knowledge_state
    if ip_type == "private":
        knowledge_state = "queued_for_inventory"
        visual_state = "queued_for_inventory"
    cluster = "provider_private" if ip_type == "private" else "unknown"
    return {
        "id": f"hop:{ip}" if ip else f"hop:unknown:cloudflare:{order}",
        "node_type": "hop",
        "label": ip or "Unknown shared hop",
        "short_label": ip.split(".")[-2] + "." + ip.split(".")[-1] if ip and ip.count(".") == 3 else f"hop {order}",
        "ip": ip,
        "cluster": cluster,
        "role": "provider_internal_transit_candidate" if ip_type == "private" else role,
        "knowledge_state": knowledge_state,
        "visual_state": visual_state,
        "position_hint": {"level": order, "branch": 0, "order": order},
        "symbol": _symbol_for_node(cluster, knowledge_state, ip_type),
        "known_before": True,
        "observed_now": True,
        "confidence": confidence,
        "operator_message": "Evidência reaproveitada de hops compartilhados; não há run dedicada para este serviço.",
        "metadata": {
            "demo_mode": True,
            "read_only": True,
            "shared_service_hops_only": True,
            "source_refs": ["routegraph/service/cloudflare", "routegraph/service/google", "external_route_inventory/shared_hops"],
            "trace_hop": row.get("min_hop_number"),
            "observations_count": int(row.get("observation_count") or row.get("occurrence_count") or 0),
            "services_seen": ["cloudflare", "google"],
            "category": row.get("category"),
            "organization": row.get("organization"),
            "country": row.get("country"),
            "reverse_dns": row.get("reverse_dns"),
            "demo_visual_anchor": False,
        },
    }


def _build_cloudflare_shared_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges = [_build_demo_anchor_edge()]
    hop_nodes = [node for node in nodes if node.get("node_type") == "hop"]
    if hop_nodes:
        edges[0]["target"] = hop_nodes[0]["id"]
        edges[0]["id"] = f"edge:origin:local->{hop_nodes[0]['id']}"
        edges[0]["metadata"]["source_refs"] = ["routegraph/global", "external_route_inventory/shared_hops"]
    for index, (source, target) in enumerate(zip(hop_nodes, hop_nodes[1:]), start=1):
        edges.append(
            {
                "id": f"edge:cloudflare-shared:{index:02d}",
                "source": source["id"],
                "target": target["id"],
                "edge_type": "route_hop",
                "transition_type": "shared_service_hop_sequence",
                "observed_now": True,
                "known_before": True,
                "visual_state": "limited",
                "confidence": 0.56,
                "operator_message": "Sequência reaproveitada de caminho compartilhado persistido; sem run dedicada Cloudflare.",
                "metadata": {
                    "demo_mode": True,
                    "read_only": True,
                    "shared_service_hops_only": True,
                    "source_refs": ["routegraph/service/google", "external_route_inventory/shared_hops"],
                    "demo_visual_anchor": False,
                },
            }
        )
    return edges


def _build_shared_steps(nodes: list[dict[str, Any]], service_slug: str) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    hop_nodes = [node for node in nodes if node.get("node_type") == "hop"]
    previous_hop_ip: str | None = None
    for index, node in enumerate(hop_nodes, start=1):
        ip = node.get("ip")
        next_ip = hop_nodes[index].get("ip") if index < len(hop_nodes) else None
        steps.append(
            {
                "step_uid": f"step-{service_slug}-shared-{index:02d}",
                "step_index": index,
                "hop_ip": ip,
                "previous_hop": previous_hop_ip,
                "next_hop": next_ip,
                "known_before": bool(node.get("known_before")),
                "observed_now": bool(node.get("observed_now")),
                "knowledge_state": node.get("knowledge_state"),
                "evidence_source": "external_route_inventory/shared_service_hops",
                "learning_action": "classify_private_path",
                "queue_status": "queued",
                "confidence": node.get("confidence"),
                "operator_message": "Evidência reaproveitada de hops compartilhados; não há run dedicada para este serviço.",
                "visual_state": node.get("visual_state"),
            }
        )
        previous_hop_ip = ip
    return steps


def _build_cloudflare_ignorance_events(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dedicated_run_plan = _build_cloudflare_dedicated_run_plan()
    events = [
        {
            "event_uid": "ie-cloudflare-01",
            "event_type": "no_dedicated_trace_run",
            "object_type": "service",
            "object_id": "service:cloudflare",
            "revealed_by": "route_learning_demo_cloudflare",
            "evidence": "Cloudflare has persisted service hops, but no persisted external_route_traceroute_runs row.",
            "priority": "high",
            "next_action": "plan_dedicated_trace_when_operator_confirms",
            "requires_active_action": True,
            "can_learn_in_background": False,
            "plan_uid": dedicated_run_plan["plan_uid"],
            "operator_message": "Não há run dedicada; o payload fica parcial e read-only.",
        }
    ]
    for index, node in enumerate([node for node in nodes if node.get("node_type") == "hop"][:4], start=2):
        events.append(
            {
                "event_uid": f"ie-cloudflare-{index:02d}",
                "event_type": "private_hop_no_public_rdap",
                "object_type": "hop",
                "object_id": node["id"],
                "revealed_by": "route_learning_demo_cloudflare",
                "evidence": "Private shared hop has no public RDAP and no dedicated Cloudflare trace context.",
                "priority": "normal",
                "next_action": "classify_private_path",
                "requires_active_action": False,
                "can_learn_in_background": True,
                "operator_message": "Hop privado compartilhado precisa de classificação local/histórica.",
            }
        )
    return events


def _build_cloudflare_learning_queue(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dedicated_run_plan = _build_cloudflare_dedicated_run_plan()
    queue = [
        {
            "queue_uid": "lq-cloudflare-01",
            "object_type": "service",
            "object_id": "service:cloudflare",
            "reason": "no_dedicated_trace_run",
            "priority_score": 91,
            "priority_reasons": ["service_has_persisted_hops", "no_dedicated_trace_run", "shared_service_hops_only"],
            "status": "waiting_consent",
            "planned_actions": ["plan_dedicated_trace_when_operator_confirms"],
            "requires_consent": True,
            "operator_message": "Planejar run dedicada apenas quando o operador confirmar.",
            "plan_uid": dedicated_run_plan["plan_uid"],
        }
    ]
    for index, node in enumerate([node for node in nodes if node.get("node_type") == "hop"][:3], start=2):
        queue.append(
            {
                "queue_uid": f"lq-cloudflare-{index:02d}",
                "object_type": "hop",
                "object_id": node["id"],
                "reason": "shared_hop_needs_context",
                "priority_score": 74 - index,
                "priority_reasons": ["shared_service_hop", "provider_private_path", "missing_role_classification"],
                "status": "queued",
                "planned_actions": ["classify_private_path", "search_historical_observations"],
                "requires_consent": False,
                "operator_message": "Classificar hop compartilhado usando histórico local já persistido.",
            }
        )
    return queue


def _build_cloudflare_dedicated_run_plan() -> dict[str, Any]:
    plan_uid = "plan-cloudflare-dedicated-trace-v1"
    return {
        "plan_uid": plan_uid,
        "target": {
            "target_type": "service",
            "value": "cloudflare",
            "resolved_ips": ["1.1.1.1"],
            "selected_ip": "1.1.1.1",
            "label": "Cloudflare dedicado",
            "importance": "normal",
        },
        "service": "cloudflare",
        "status": "waiting_operator_confirmation",
        "reason": "nao_existe_run_dedicada_e_o_caminho_atual_usa_hops_compartilhados",
        "revealed_by": "route_learning_cloudflare_partial_payload",
        "expected_learning": [
            "create_path_for_cloudflare_or_1_1_1_1",
            "replace_shared_service_hops_only_with_dedicated_trace_evidence",
            "discover_real_edges",
            "confirm_or_reject_common_trunk_with_google",
            "identify_real_bifurcation",
            "improve_node_edge_confidence",
            "prepare_future_cloudflare_route_profile",
        ],
        "proposed_actions": [
            "resolve_target_if_needed",
            "active_trace_cloudflare_when_confirmed",
            "persist_dedicated_edges",
            "rebuild_route_learning_payload",
            "compare_with_google_common_trunk",
            "update_learning_queue",
        ],
        "safety_policy": {
            "read_only_plan": True,
            "no_execution_in_this_request": True,
            "max_targets": 1,
            "allowed_targets": ["1.1.1.1", "cloudflare.com"],
            "require_admin": True,
            "require_confirm": True,
            "no_private_target": True,
            "no_payload_capture": True,
            "no_url_query_capture": True,
            "no_bgp_cursor_change": True,
        },
        "requires_operator_confirmation": True,
        "required_role": "admin",
        "active_action_executed": False,
        "audit_requirements": [
            "record_operator_confirmation_before_execution",
            "confirm_target_and_scope_before_measurement",
            "log_no_active_action_taken_in_planning_phase",
        ],
        "limitations": [
            "read_only_only",
            "no_active_measurement",
            "no_ping",
            "no_traceroute",
            "no_mikrotik_collection",
            "no_external_enrichment",
            "no_database_write",
            "shared_service_hops_only",
            "no_dedicated_trace_run",
            "no_cloudflare_edges_persisted",
            "no_destination_final_hop_asserted",
        ],
        "operator_message": "Plano de medicao dedicada Cloudflare controlado por confirmacao explicita de admin; este bloco nao executa nova acao por leitura.",
    }


def _build_cloudflare_post_change_run_plan(*, plan_uid: str, target: str, ip_family: str) -> dict[str, Any]:
    return {
        "plan_uid": plan_uid,
        "service_uid": _CLOUDFLARE_SERVICE,
        "target": target,
        "ip_family": ip_family,
        "baseline_type": "post_local_network_change",
        "local_change_event": "nat_reduced_ipv6_enabled",
        "local_change_event_at": "2026-06-11",
        "requires_operator_confirmation": True,
        "required_role": "admin",
        "active_action_executed": False,
        "safety_status": "waiting_operator_confirmation",
        "status": "waiting_operator_confirmation",
        "reason": "planejamento_de_nova_run_dedicada_pos_mudanca_local_sem_execucao_ativa",
        "revealed_by": "route_learning_cloudflare_post_change_plan",
        "expected_learning": [
            "create_ipv4_or_ipv6_baseline_after_local_network_change",
            "separate_ipv4_and_ipv6_route_series",
            "preserve_silent_hops_and_edge_counts",
            "avoid_cross_family_comparison",
            "prepare_future_temporal_comparison_only_after_real_collection",
        ],
        "proposed_actions": [
            "confirm_admin_only",
            "validate_plan_uid_and_allowlisted_target",
            "run_dedicated_trace_only_when_explicitly_confirmed",
            "persist_dedicated_edges_if_execution_is_allowed",
        ],
        "safety_policy": {
            "read_only_plan": True,
            "no_execution_in_this_request": True,
            "max_targets": 1,
            "allowed_targets": [target],
            "allowed_ip_families": [ip_family],
            "require_admin": True,
            "require_confirm": True,
            "no_private_target": True,
            "no_link_local_target": True,
            "no_multicast_target": True,
            "no_reserved_target": True,
            "no_payload_capture": True,
            "no_url_query_capture": True,
            "no_bgp_cursor_change": True,
        },
        "audit_requirements": [
            "record_operator_confirmation_before_execution",
            "confirm_target_family_and_scope_before_measurement",
            "log_no_active_action_taken_in_planning_phase",
        ],
        "limitations": [
            "read_only_only",
            "no_active_measurement",
            "no_ping",
            "no_traceroute",
            "no_mikrotik_collection",
            "no_external_enrichment",
            "no_database_write",
            "no_final_destination_assertion",
        ],
        "operator_message": "Plano declarativo para a próxima run dedicada pós-mudança local. Nenhuma ação ativa é executada neste payload.",
    }


def _build_cloudflare_post_change_run_plans() -> dict[str, Any]:
    plans = [
        _build_cloudflare_post_change_run_plan(
            plan_uid="plan-cloudflare-ipv4-post-nat-ipv6-change-v1",
            target="1.1.1.1",
            ip_family="ipv4",
        ),
        _build_cloudflare_post_change_run_plan(
            plan_uid="plan-cloudflare-ipv6-post-nat-ipv6-change-v1",
            target="2606:4700:4700::1111",
            ip_family="ipv6",
        ),
    ]
    return {
        "service_uid": _CLOUDFLARE_SERVICE,
        "baseline_type": "post_local_network_change",
        "local_change_event": "nat_reduced_ipv6_enabled",
        "local_change_event_at": "2026-06-11",
        "requires_operator_confirmation": True,
        "required_role": "admin",
        "active_action_executed": False,
        "safety_status": "waiting_operator_confirmation",
        "status": "planned",
        "plans": plans,
        "operator_message": "Dois planos read-only separados: IPv4 para 1.1.1.1 e IPv6 para 2606:4700:4700::1111. A execução ativa continua bloqueada até confirmação explícita de admin.",
        "metadata": {
            "measurement_context": {
                "baseline_type": "post_local_network_change",
                "local_change_event": "nat_reduced_ipv6_enabled",
                "local_change_event_at": "2026-06-11",
                "ip_family_series": ["ipv4", "ipv6"],
                "target_allowlist": ["1.1.1.1", "2606:4700:4700::1111"],
            }
        },
    }


def _cloudflare_dedicated_trace_state(service_slug: str = _CLOUDFLARE_SERVICE) -> dict[str, Any]:
    service_summary = get_service_route_summary(service_slug)
    latest_trace_run = service_summary.get("latest_trace_run") if isinstance(service_summary, dict) else {}
    if not isinstance(latest_trace_run, dict):
        latest_trace_run = {}
    metadata = latest_trace_run.get("metadata") if isinstance(latest_trace_run.get("metadata"), dict) else {}
    route_learning = metadata.get("route_learning") if isinstance(metadata.get("route_learning"), dict) else {}
    if isinstance(route_learning, dict) and isinstance(route_learning.get("route_learning"), dict):
        route_learning = route_learning.get("route_learning") or {}
    dedicated_run_uid = str(latest_trace_run.get("run_uid") or "")
    dedicated_trace_evidence = bool(
        dedicated_run_uid
        and route_learning.get("execution_type") == "dedicated_trace_run"
        and _is_cloudflare_dedicated_trace_plan(route_learning.get("plan_uid"))
    )
    dedicated_graph = get_external_route_trace_graph(dedicated_run_uid) if dedicated_trace_evidence else {"available": False}
    comparison = compare_service_routes("google", service_slug).get("comparison") or {}
    shared_examples = comparison.get("shared_examples") or []
    summary_rows = service_summary.get("hops") or []
    limitations_remaining: list[str] = []
    if any(row.get("asn") is None for row in summary_rows):
        limitations_remaining.append("missing_asn")
    if any(row.get("reverse_dns") is None for row in summary_rows):
        limitations_remaining.append("missing_reverse_dns")
    if any((row.get("category") == "unknown" or row.get("confidence") == "unknown") for row in summary_rows):
        limitations_remaining.append("icmp_silent_hops")
    if any((row.get("category") == "private" or row.get("role") == "private") for row in summary_rows):
        limitations_remaining.append("private_hop_no_public_rdap")
    limitations_remaining = list(dict.fromkeys(limitations_remaining))
    trace_nodes = dedicated_graph.get("nodes") or []
    trace_edges = dedicated_graph.get("edges") or []
    target_resolved_ip = str(latest_trace_run.get("target_resolved_ip") or "")
    final_destination_asserted = bool(
        dedicated_trace_evidence
        and trace_nodes
        and target_resolved_ip
        and str(trace_nodes[-1].get("ip") or "") == target_resolved_ip
    )
    return {
        "service_summary": service_summary,
        "latest_trace_run": latest_trace_run,
        "route_learning": route_learning,
        "dedicated_run_uid": dedicated_run_uid or None,
        "dedicated_trace_evidence": dedicated_trace_evidence,
        "dedicated_graph": dedicated_graph,
        "dedicated_graph_nodes": trace_nodes,
        "dedicated_graph_edges": trace_edges,
        "shared_comparison": comparison,
        "shared_examples": shared_examples,
        "final_destination_asserted": final_destination_asserted,
        "limitations_remaining": limitations_remaining,
        "status": str(latest_trace_run.get("status") or service_summary.get("status") or "partial"),
    }


def _cloudflare_dedicated_runs(service_slug: str = _CLOUDFLARE_SERVICE, target: str | None = None) -> list[dict[str, Any]]:
    normalized_target = _normalize_ip(target) or str(target).strip().lower() if target else None
    where_clauses = ["service_uid = %s"]
    params: list[Any] = [service_slug]
    if normalized_target:
        where_clauses.append(
            "("
            "lower(coalesce(target_host, '')) = %s or "
            "lower(coalesce(target_uid::text, '')) = %s or "
            "target_resolved_ip::text = %s or "
            "target_resolved_ip::text = %s::text"
            ")"
        )
        params.extend([normalized_target, normalized_target, normalized_target, f"{normalized_target}/32"])
    where_clauses.append(
        "coalesce(metadata #>> '{route_learning,route_learning,execution_type}', metadata #>> '{route_learning,execution_type}') = 'dedicated_trace_run'"
    )
    sql = f"""
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
          requested_by_role,
          requested_by_username,
          observed_at,
          completed_at,
          metadata
        from external_route_traceroute_runs
        where {' and '.join(where_clauses)}
        order by observed_at asc, completed_at asc nulls last, run_uid asc;
    """
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, tuple(params))
            return [dict(row) for row in cur.fetchall()]


def _dedicated_run_metadata(run_row: dict[str, Any] | None) -> dict[str, Any]:
    metadata = run_row.get("metadata") if isinstance(run_row, dict) and isinstance(run_row.get("metadata"), dict) else {}
    route_learning = metadata.get("route_learning") if isinstance(metadata.get("route_learning"), dict) else {}
    if isinstance(route_learning, dict) and isinstance(route_learning.get("route_learning"), dict):
        route_learning = route_learning.get("route_learning") or {}
    return route_learning


def _build_cloudflare_profile_snapshot_from_run(
    run_row: dict[str, Any] | None,
    *,
    service_slug: str = _CLOUDFLARE_SERVICE,
    route_profile: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(run_row, dict):
        return None
    run_uid = str(run_row.get("run_uid") or "").strip()
    if not run_uid:
        return None
    trace_graph = get_external_route_trace_graph(run_uid)
    trace_nodes = trace_graph.get("nodes") or []
    trace_edges = trace_graph.get("edges") or []
    route_learning = _dedicated_run_metadata(run_row)
    target_value = str(run_row.get("target_resolved_ip") or trace_graph.get("target_resolved_ip") or run_row.get("target_host") or "1.1.1.1")
    node_ips = [str(node.get("ip")) for node in trace_nodes if node.get("ip")]
    first_hop = node_ips[0] if node_ips else None
    last_observed_hop = node_ips[-1] if node_ips else None
    private_hop_count = sum(1 for node in trace_nodes if node.get("ip") and ipaddress.ip_address(str(node.get("ip"))).is_private)
    public_hop_count = sum(1 for node in trace_nodes if node.get("ip") and not ipaddress.ip_address(str(node.get("ip"))).is_private)
    silent_hop_count = sum(1 for node in trace_nodes if not node.get("ip"))
    hop_fingerprint_source = "|".join(
        f"{int(node.get('hop') or 0)}:{node.get('ip') or '*'}:{node.get('role') or 'unknown'}:{node.get('confidence') or 'unknown'}"
        for node in trace_nodes
    )
    edge_fingerprint_source = "|".join(
        f"{int(edge.get('from_hop_index') or 0)}>{int(edge.get('to_hop_index') or 0)}:{edge.get('transition_type') or 'unknown'}:{edge.get('from_hop_ip') or '*'}->{edge.get('to_hop_ip') or '*'}"
        for edge in trace_edges
    )
    hop_fingerprint = hashlib.sha256(hop_fingerprint_source.encode("utf-8")).hexdigest()[:20] if hop_fingerprint_source else None
    edge_fingerprint = hashlib.sha256(edge_fingerprint_source.encode("utf-8")).hexdigest()[:20] if edge_fingerprint_source else None

    route_profile = route_profile or build_route_profile(service_slug, target_value)
    asn_status = route_profile.get("asn_attribution_status") if isinstance(route_profile, dict) else {}
    limitations = route_profile.get("limitations") if isinstance(route_profile, dict) else []
    if not isinstance(limitations, list):
        limitations = []
    counting_semantics = {
        "hop_count_alias": "logical_hop_count",
        "logical_hop_count_description": "total TTL/path positions, including silent hops",
        "responding_hop_count_description": "hops that returned an IP/ICMP response",
        "silent_hop_count_description": "logical hops without ICMP response",
        "edge_count_description": "transitions between logical consecutive hop positions",
    }
    path_signature = {
        "first_hop": first_hop,
        "last_observed_hop": last_observed_hop,
        "public_hop_count": public_hop_count,
        "private_hop_count": private_hop_count,
        "silent_hop_count": silent_hop_count,
        "hop_fingerprint": hop_fingerprint,
        "edge_fingerprint": edge_fingerprint,
        "path_length": len(trace_nodes),
        "logical_hop_count": len(trace_nodes),
        "responding_hop_count": int(run_row.get("hop_count") or len(node_ips) or 0),
        "evidence_source": "external_route_inventory.external_route_traceroute_runs",
    }
    return {
        "profile_uid": f"profile-{_safe_uid_fragment(service_slug)}-{run_uid}",
        "service": service_slug,
        "target": target_value,
        "dedicated_run_uid": run_uid,
        "observed_at": str(run_row.get("observed_at") or run_row.get("completed_at") or _now().isoformat()),
        "hop_count": int((route_profile.get("route_summary") or {}).get("hop_count") or run_row.get("hop_count") or len(trace_nodes) or 0),
        "edge_count": int((route_profile.get("route_summary") or {}).get("edge_count") or run_row.get("edge_count") or len(trace_edges) or 0),
        "path_signature": path_signature,
        "confidence": str(route_profile.get("confidence") or "partial"),
        "final_destination_asserted": bool(route_profile.get("route_summary", {}).get("final_destination_asserted")) if isinstance(route_profile.get("route_summary"), dict) else False,
        "limitations": list(limitations),
        "counting_semantics": counting_semantics,
        "asn_attribution_summary": {
            "total_hops": asn_status.get("total_hops") or len(trace_nodes),
            "hops_without_asn": asn_status.get("hops_without_asn"),
            "private_ip_hops": asn_status.get("private_ip_hops") or private_hop_count,
            "icmp_silent_hops": asn_status.get("icmp_silent_hops") or silent_hop_count,
            "public_hop_count": public_hop_count,
            "logical_hop_count": len(trace_nodes),
            "responding_hop_count": int(run_row.get("hop_count") or len(node_ips) or 0),
            "silent_hop_count": silent_hop_count,
            "attribution_engine_status": asn_status.get("attribution_engine_status"),
        },
        "route_profile": route_profile,
        "route_graph": trace_graph,
        "trace_nodes": trace_nodes,
        "trace_edges": trace_edges,
        "metadata": {
            "run_uid": run_uid,
            "target_host": run_row.get("target_host"),
            "target_resolved_ip": run_row.get("target_resolved_ip"),
            "execution_type": route_learning.get("execution_type") if isinstance(route_learning, dict) else None,
            "plan_uid": route_learning.get("plan_uid") if isinstance(route_learning, dict) else None,
        },
    }


def _build_temporal_comparable_dimension(
    name: str,
    current_value: Any,
    previous_value: Any,
    *,
    current_available: bool = True,
    previous_available: bool = True,
    operator_message: str | None = None,
) -> dict[str, Any]:
    if not previous_available:
        return {
            "name": name,
            "current_available": current_available,
            "previous_available": False,
            "comparison_status": "waiting_for_future_baseline",
            "current_value": current_value,
            "previous_value": None,
            "delta": None,
            "operator_message": operator_message or "Ainda não há baseline anterior dedicado para comparar este dimensionamento.",
        }
    delta: Any = None
    if isinstance(current_value, (int, float)) and isinstance(previous_value, (int, float)):
        delta = current_value - previous_value
    elif current_value != previous_value:
        delta = {"from": previous_value, "to": current_value}
    return {
        "name": name,
        "current_available": current_available,
        "previous_available": True,
        "comparison_status": "compared",
        "current_value": current_value,
        "previous_value": previous_value,
        "delta": delta,
        "operator_message": operator_message or "Comparação temporal concluída para esta dimensão.",
    }


def _temporal_delta_changed(delta: Any) -> bool:
    return not (delta is None or delta == 0 or delta == "" or delta is False or delta == {} or delta == [])


def _build_temporal_profile_comparison_result(
    current_profile: dict[str, Any],
    previous_profile: dict[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(previous_profile, dict):
        return {
            "status": "not_compared",
            "route_changed": "unknown",
            "reason": "no_previous_profile",
            "changed_dimensions": [],
            "unchanged_dimensions": [],
            "inconclusive_dimensions": [
                "hop_count",
                "edge_count",
                "path_signature",
                "first_hop",
                "last_observed_hop",
                "common_trunk_with_google",
                "private_hop_count",
                "public_hop_count",
                "silent_hop_count",
                "missing_asn_count",
                "missing_reverse_dns_count",
                "final_destination_asserted",
                "confidence",
                "limitations_count",
            ],
            "operator_message": "Não dá para afirmar mudança temporal ainda; esta run dedicada passa a ser o baseline inicial.",
        }

    current_dims = current_profile.get("route_profile", {}).get("route_summary", {}) if isinstance(current_profile.get("route_profile"), dict) else {}
    previous_dims = previous_profile.get("route_profile", {}).get("route_summary", {}) if isinstance(previous_profile, dict) and isinstance(previous_profile.get("route_profile"), dict) else {}
    changed = []
    unchanged = []
    inconclusive = []
    for key in ("hop_count", "edge_count", "final_destination_asserted", "confidence"):
        if current_dims.get(key) == previous_dims.get(key):
            unchanged.append(key)
        else:
            changed.append(key)
    if not changed:
        route_changed = "false"
    else:
        route_changed = "true"
    return {
        "status": "compared",
        "route_changed": route_changed,
        "changed_dimensions": changed,
        "unchanged_dimensions": unchanged,
        "inconclusive_dimensions": inconclusive,
        "operator_message": "Comparação temporal concluída entre runs dedicadas persistidas.",
    }


def build_temporal_profile_comparison(service: str, target: str | None = None) -> dict[str, Any]:
    service_slug = _normalize_service(service)
    normalized_target = _normalize_ip(target) or str(target).strip() if target else "cloudflare"
    comparison_uid = f"cmp-{_safe_uid_fragment(service_slug)}-temporal-profile"
    if service_slug != _CLOUDFLARE_SERVICE or normalized_target not in {"cloudflare", "cloudflare.com", "1.1.1.1"}:
        return {
            "comparison_uid": comparison_uid,
            "service": service_slug,
            "target": normalized_target,
            "status": "partial",
            "generated_at": _now().isoformat(),
            "current_profile": None,
            "previous_profile": None,
            "baseline_availability": {
                "status": "unsupported_temporal_comparison",
                "reason": "unsupported_service_or_target",
            },
            "comparable_dimensions": [],
            "comparison_result": {
                "status": "not_compared",
                "route_changed": "unknown",
                "reason": "unsupported_service_or_target",
                "changed_dimensions": [],
                "unchanged_dimensions": [],
                "inconclusive_dimensions": [],
                "operator_message": "Comparação temporal read-only disponível apenas para Cloudflare/1.1.1.1 nesta rodada.",
            },
            "knowledge_delta": {
                "status": "unsupported_temporal_comparison",
                "learned_now": [],
                "still_unknown": [],
                "operator_message": "Comparação temporal não suportada para este alvo nesta rodada.",
            },
            "route_delta": {
                "status": "unsupported_temporal_comparison",
                "changed_edges": [],
                "added_edges": [],
                "removed_edges": [],
                "operator_message": "Não há comparação temporal suportada para este alvo nesta rodada.",
            },
            "ignorance_delta": {
                "status": "unsupported_temporal_comparison",
                "current_remaining_ignorance": [],
                "previous_remaining_ignorance": None,
                "operator_message": "Ignorância temporal não avaliada para este alvo nesta rodada.",
            },
            "confidence": "low",
            "limitations": ["unsupported_temporal_comparison"],
            "operator_message": "Comparação temporal read-only disponível apenas para Cloudflare/1.1.1.1 nesta rodada.",
            "metadata": {"demo_mode": True, "builder_mode": "temporal_profile_comparison", "unsupported": True},
        }

    runs = _cloudflare_dedicated_runs(service_slug, normalized_target)
    latest_run = runs[-1] if runs else None
    previous_run = runs[-2] if len(runs) > 1 else None
    current_profile = _build_cloudflare_profile_snapshot_from_run(latest_run, service_slug=service_slug) if latest_run else None
    previous_profile = _build_cloudflare_profile_snapshot_from_run(previous_run, service_slug=service_slug) if previous_run else None
    current_profile_dict = current_profile if isinstance(current_profile, dict) else {}
    previous_profile_dict = previous_profile if isinstance(previous_profile, dict) else {}
    current_measurement_context = current_profile_dict.get("measurement_context") if isinstance(current_profile_dict.get("measurement_context"), dict) else {}
    current_route_profile = current_profile_dict.get("route_profile") if current_profile_dict else build_route_profile(service_slug, normalized_target)
    previous_route_profile = previous_profile_dict.get("route_profile") if previous_profile_dict else None
    if current_profile is None:
        return {
            "comparison_uid": comparison_uid,
            "service": service_slug,
            "target": normalized_target,
            "status": "baseline_missing",
            "generated_at": _now().isoformat(),
            "current_profile": None,
            "previous_profile": None,
            "baseline_availability": {
                "status": "missing",
                "reason": "no_previous_dedicated_route_profile",
            },
            "comparable_dimensions": [],
            "comparison_result": {
                "status": "not_compared",
                "route_changed": "unknown",
                "reason": "no_current_profile",
                "changed_dimensions": [],
                "unchanged_dimensions": [],
                "inconclusive_dimensions": [],
                "operator_message": "Não foi possível localizar um perfil Cloudflare persistido para esta comparação.",
            },
            "knowledge_delta": {
                "status": "baseline_created",
                "learned_now": [],
                "still_unknown": [],
                "operator_message": "Ainda não há perfil dedicado para comparação temporal.",
            },
            "route_delta": {
                "status": "waiting_for_next_profile",
                "changed_edges": [],
                "added_edges": [],
                "removed_edges": [],
                "operator_message": "A próxima run dedicada será a primeira comparação temporal real.",
            },
            "ignorance_delta": {
                "status": "baseline_only",
                "current_remaining_ignorance": [],
                "previous_remaining_ignorance": None,
                "operator_message": "Sem profile atual persistido para comparar ignorância temporal.",
            },
            "confidence": "partial",
            "limitations": ["missing_current_profile"],
            "operator_message": "Ainda não há perfil persistido suficiente para comparação temporal.",
            "metadata": {"demo_mode": True, "builder_mode": "temporal_profile_comparison", "runs_seen": len(runs)},
        }

    current_trace_graph = current_profile_dict.get("route_graph") if current_profile_dict else {}
    previous_trace_graph = previous_profile_dict.get("route_graph") if previous_profile_dict else {}
    current_edges = current_trace_graph.get("edges") or []
    previous_edges = previous_trace_graph.get("edges") or []
    current_edge_signatures = {
        f"{edge.get('from_hop_index')}->{edge.get('to_hop_index')}:{edge.get('transition_type')}:{edge.get('from_hop_ip')}->{edge.get('to_hop_ip')}"
        for edge in current_edges
    }
    previous_edge_signatures = {
        f"{edge.get('from_hop_index')}->{edge.get('to_hop_index')}:{edge.get('transition_type')}:{edge.get('from_hop_ip')}->{edge.get('to_hop_ip')}"
        for edge in previous_edges
    }
    added_edges = sorted(current_edge_signatures - previous_edge_signatures)
    removed_edges = sorted(previous_edge_signatures - current_edge_signatures)
    changed_edges = sorted(current_edge_signatures & previous_edge_signatures)

    current_path = current_profile_dict.get("path_signature") if isinstance(current_profile_dict.get("path_signature"), dict) else {}
    previous_path = previous_profile_dict.get("path_signature") if isinstance(previous_profile_dict.get("path_signature"), dict) else {}
    current_limits = current_profile_dict.get("limitations") or []
    previous_limits = previous_profile_dict.get("limitations") or []
    current_asn = current_profile_dict.get("asn_attribution_summary") if isinstance(current_profile_dict.get("asn_attribution_summary"), dict) else {}
    previous_asn = previous_profile_dict.get("asn_attribution_summary") if isinstance(previous_profile_dict.get("asn_attribution_summary"), dict) else {}
    comparable_dimensions = [
        _build_temporal_comparable_dimension("hop_count", current_profile_dict.get("hop_count"), previous_profile_dict.get("hop_count")),
        _build_temporal_comparable_dimension("edge_count", current_profile_dict.get("edge_count"), previous_profile_dict.get("edge_count")),
        _build_temporal_comparable_dimension("path_signature", current_path, previous_path),
        _build_temporal_comparable_dimension("first_hop", current_path.get("first_hop"), previous_path.get("first_hop")),
        _build_temporal_comparable_dimension("last_observed_hop", current_path.get("last_observed_hop"), previous_path.get("last_observed_hop")),
        _build_temporal_comparable_dimension(
            "common_trunk_with_google",
            current_route_profile.get("route_summary", {}).get("common_trunk_with_google") if isinstance(current_route_profile, dict) else None,
            previous_route_profile.get("route_summary", {}).get("common_trunk_with_google") if isinstance(previous_route_profile, dict) else None,
        ),
        _build_temporal_comparable_dimension("private_hop_count", current_path.get("private_hop_count"), previous_path.get("private_hop_count")),
        _build_temporal_comparable_dimension("public_hop_count", current_path.get("public_hop_count"), previous_path.get("public_hop_count")),
        _build_temporal_comparable_dimension("silent_hop_count", current_path.get("silent_hop_count"), previous_path.get("silent_hop_count")),
        _build_temporal_comparable_dimension("missing_asn_count", current_asn.get("hops_without_asn"), previous_asn.get("hops_without_asn")),
        _build_temporal_comparable_dimension("missing_reverse_dns_count", len([item for item in (current_profile_dict.get("limitations") or []) if item == "missing_reverse_dns"]), len([item for item in (previous_profile_dict.get("limitations") or []) if item == "missing_reverse_dns"])),
        _build_temporal_comparable_dimension("final_destination_asserted", current_profile_dict.get("final_destination_asserted"), previous_profile_dict.get("final_destination_asserted")),
        _build_temporal_comparable_dimension("confidence", current_profile_dict.get("confidence"), previous_profile_dict.get("confidence")),
        _build_temporal_comparable_dimension("limitations_count", len(current_limits), len(previous_limits)),
    ]

    if previous_profile is None:
        baseline_availability = {
            "status": "missing",
            "reason": "no_previous_dedicated_route_profile",
        }
        comparison_result = {
            "status": "not_compared",
            "route_changed": "unknown",
            "reason": "no_previous_profile",
            "changed_dimensions": [],
            "unchanged_dimensions": [],
            "inconclusive_dimensions": [dimension["name"] for dimension in comparable_dimensions],
            "operator_message": "Não dá para afirmar mudança temporal ainda; esta run dedicada passa a ser o baseline inicial.",
        }
        knowledge_delta = {
            "status": "baseline_created",
            "learned_now": [
                "dedicated_run_exists",
                "dedicated_edges_exist",
                "route_profile_created",
                "asn_gap_marked_for_future_engine",
            ],
            "still_unknown": [
                "missing_asn",
                "missing_reverse_dns",
                "private_hop_no_public_rdap",
                "icmp_silent_hops",
                "final_destination_not_asserted",
            ],
            "operator_message": "Ainda não há baseline anterior dedicado; a run atual vira baseline inicial para futuras comparações.",
        }
        route_delta = {
            "status": "waiting_for_next_profile",
            "changed_edges": [],
            "added_edges": [],
            "removed_edges": [],
            "operator_message": "Ainda não há profile anterior dedicado equivalente; a próxima run permitirá comparar edges temporalmente.",
        }
        ignorance_delta = {
            "status": "baseline_only",
            "current_remaining_ignorance": current_profile_dict.get("limitations") or [],
            "previous_remaining_ignorance": None,
            "operator_message": "A ignorância atual fica registrada como baseline operacional, não como regressão nem melhoria temporal.",
        }
        status = "baseline_missing"
        confidence = current_profile_dict.get("confidence") or "partial"
        operator_message = "Ainda não há perfil dedicado anterior equivalente para comparação temporal. O perfil atual será o baseline para futuras comparações."
    else:
        baseline_availability = {
            "status": "available",
            "reason": "previous_dedicated_route_profile_found",
        }
        changed_dimension_names = [dimension["name"] for dimension in comparable_dimensions if dimension.get("comparison_status") == "compared" and _temporal_delta_changed(dimension.get("delta"))]
        unchanged_dimension_names = [dimension["name"] for dimension in comparable_dimensions if dimension.get("comparison_status") == "compared" and not _temporal_delta_changed(dimension.get("delta"))]
        comparison_result = {
            "status": "compared",
            "route_changed": bool(changed_dimension_names),
            "changed_dimensions": changed_dimension_names,
            "unchanged_dimensions": unchanged_dimension_names,
            "inconclusive_dimensions": [],
            "operator_message": "Comparação temporal concluída entre runs dedicadas persistidas.",
        }
        knowledge_delta = {
            "status": "compared",
            "learned_now": changed_dimension_names or ["no_structural_change_detected"],
            "still_unknown": [
                "missing_asn",
                "missing_reverse_dns",
                "private_hop_no_public_rdap",
                "icmp_silent_hops",
                "final_destination_not_asserted",
            ],
            "operator_message": "A comparação real foi feita sem execução ativa; a ignorância residual continua explícita.",
        }
        route_delta = {
            "status": "compared",
            "changed_edges": changed_edges,
            "added_edges": added_edges,
            "removed_edges": removed_edges,
            "operator_message": "Edges comparadas entre runs dedicadas persistidas.",
        }
        ignorance_delta = {
            "status": "compared",
            "current_remaining_ignorance": current_profile_dict.get("limitations") or [],
            "previous_remaining_ignorance": previous_profile_dict.get("limitations") or [],
            "operator_message": "A comparação temporal mostrou a ignorância residual por diferenças estruturais observadas.",
        }
        status = "compared"
        confidence = current_profile_dict.get("confidence") or previous_profile_dict.get("confidence") or "partial"
        operator_message = "Comparação temporal real concluída entre runs dedicadas persistidas."

    return {
        "comparison_uid": comparison_uid,
        "service": service_slug,
        "target": normalized_target,
        "status": status,
        "generated_at": _now().isoformat(),
        "measurement_context": {
            "baseline_type": current_measurement_context.get("baseline_type") or "pre_local_network_change",
            "local_change_event": current_measurement_context.get("local_change_event") or "nat_reduced_ipv6_enabled",
            "local_change_event_at": current_measurement_context.get("local_change_event_at") or "2026-06-11",
            "ip_family": current_measurement_context.get("ip_family") or "ipv4",
            "target": current_measurement_context.get("target") or normalized_target,
            "context_note": current_measurement_context.get("context_note") or "This profile was captured before the local NAT reduction and IPv6 enablement.",
            "measurement_context_status": current_measurement_context.get("measurement_context_status") or "historical_pre_change_baseline",
        },
        "current_profile": {
            "profile_uid": current_profile_dict.get("profile_uid"),
            "dedicated_run_uid": current_profile_dict.get("dedicated_run_uid"),
            "observed_at": current_profile_dict.get("observed_at"),
            "hop_count": current_profile_dict.get("hop_count"),
            "edge_count": current_profile_dict.get("edge_count"),
            "counting_semantics": current_profile_dict.get("counting_semantics"),
            "path_signature": current_profile_dict.get("path_signature"),
            "confidence": current_profile_dict.get("confidence"),
            "final_destination_asserted": current_profile_dict.get("final_destination_asserted"),
            "limitations": current_profile_dict.get("limitations"),
            "asn_attribution_summary": current_profile_dict.get("asn_attribution_summary"),
        },
        "previous_profile": None if previous_profile is None else {
            "profile_uid": previous_profile_dict.get("profile_uid"),
            "dedicated_run_uid": previous_profile_dict.get("dedicated_run_uid"),
            "observed_at": previous_profile_dict.get("observed_at"),
            "hop_count": previous_profile_dict.get("hop_count"),
            "edge_count": previous_profile_dict.get("edge_count"),
            "counting_semantics": previous_profile_dict.get("counting_semantics"),
            "path_signature": previous_profile_dict.get("path_signature"),
            "confidence": previous_profile_dict.get("confidence"),
            "final_destination_asserted": previous_profile_dict.get("final_destination_asserted"),
            "limitations": previous_profile_dict.get("limitations"),
            "asn_attribution_summary": previous_profile_dict.get("asn_attribution_summary"),
        },
        "baseline_availability": baseline_availability,
        "comparable_dimensions": comparable_dimensions,
        "comparison_result": comparison_result,
        "knowledge_delta": knowledge_delta,
        "route_delta": route_delta,
        "ignorance_delta": ignorance_delta,
        "confidence": confidence,
        "limitations": [
            "read_only_only",
            "no_active_measurement",
            "no_ping",
            "no_traceroute",
            "no_database_write",
            "baseline_missing" if previous_profile is None else "comparison_real",
        ],
        "operator_message": operator_message,
        "metadata": {
            "demo_mode": True,
            "builder_mode": "temporal_profile_comparison",
            "dedicated_run_count": len(runs),
            "current_run_uid": current_profile_dict.get("dedicated_run_uid"),
            "previous_run_uid": previous_profile_dict.get("dedicated_run_uid") if previous_profile else None,
            "current_route_profile_uid": current_profile_dict.get("profile_uid"),
            "previous_route_profile_uid": previous_profile_dict.get("profile_uid") if previous_profile else None,
            "measurement_context": {
                "baseline_type": current_measurement_context.get("baseline_type") or "pre_local_network_change",
                "local_change_event": current_measurement_context.get("local_change_event") or "nat_reduced_ipv6_enabled",
                "local_change_event_at": current_measurement_context.get("local_change_event_at") or "2026-06-11",
                "ip_family": current_measurement_context.get("ip_family") or "ipv4",
                "target": current_measurement_context.get("target") or normalized_target,
                "context_note": current_measurement_context.get("context_note") or "This profile was captured before the local NAT reduction and IPv6 enablement.",
                "measurement_context_status": current_measurement_context.get("measurement_context_status") or "historical_pre_change_baseline",
            },
            "supported_targets": ["1.1.1.1", "cloudflare", None],
        },
    }


def _cloudflare_route_profile_state(service_slug: str = _CLOUDFLARE_SERVICE) -> dict[str, Any]:
    state = _cloudflare_dedicated_trace_state(service_slug)
    latest_trace_run = state.get("latest_trace_run") if isinstance(state.get("latest_trace_run"), dict) else {}
    if not isinstance(latest_trace_run, dict):
        latest_trace_run = {}
    trace_graph = state.get("dedicated_graph") if isinstance(state.get("dedicated_graph"), dict) else {}
    trace_nodes = state.get("dedicated_graph_nodes") or []
    trace_edges = state.get("dedicated_graph_edges") or []
    service_summary = state.get("service_summary") if isinstance(state.get("service_summary"), dict) else {}
    summary_rows = service_summary.get("hops") or []
    rows_by_ip = {str(row.get("hop_ip") or "").split("/")[0]: row for row in summary_rows if row.get("hop_ip")}

    profile_uid = f"profile-{_safe_uid_fragment(service_slug)}-cloudflare-dedicated-trace-v1"
    target_value = str(latest_trace_run.get("target_resolved_ip") or trace_graph.get("target_resolved_ip") or "1.1.1.1")
    generated_at = _now().isoformat()
    last_observed_at = str(latest_trace_run.get("completed_at") or latest_trace_run.get("observed_at") or generated_at)
    dedicated_run_uid = state.get("dedicated_run_uid")
    route_learning = state.get("route_learning") if isinstance(state.get("route_learning"), dict) else {}
    dedicated_trace_evidence = bool(state.get("dedicated_trace_evidence"))
    shared_comparison = state.get("shared_comparison") if isinstance(state.get("shared_comparison"), dict) else {}
    shared_examples = state.get("shared_examples") or []
    dedicated_runs = _cloudflare_dedicated_runs(service_slug, target_value)
    dedicated_run_count = len(dedicated_runs)

    node_ips = [str(node.get("ip")) for node in trace_nodes if node.get("ip")]
    first_hop = node_ips[0] if node_ips else None
    last_observed_hop = node_ips[-1] if node_ips else None
    private_hop_count = sum(1 for node in trace_nodes if node.get("ip") and ipaddress.ip_address(str(node.get("ip"))).is_private)
    public_hop_count = sum(1 for node in trace_nodes if node.get("ip") and not ipaddress.ip_address(str(node.get("ip"))).is_private)
    silent_hop_count = sum(1 for node in trace_nodes if not node.get("ip"))
    path_length = len(trace_nodes)
    hop_fingerprint_source = "|".join(
        f"{int(node.get('hop') or 0)}:{node.get('ip') or '*'}:{node.get('role') or 'unknown'}:{node.get('confidence') or 'unknown'}"
        for node in trace_nodes
    )
    edge_fingerprint_source = "|".join(
        f"{int(edge.get('from_hop_index') or 0)}>{int(edge.get('to_hop_index') or 0)}:{edge.get('transition_type') or 'unknown'}:{edge.get('from_hop_ip') or '*'}->{edge.get('to_hop_ip') or '*'}"
        for edge in trace_edges
    )
    hop_fingerprint = hashlib.sha256(hop_fingerprint_source.encode("utf-8")).hexdigest()[:20] if hop_fingerprint_source else None
    edge_fingerprint = hashlib.sha256(edge_fingerprint_source.encode("utf-8")).hexdigest()[:20] if edge_fingerprint_source else None
    counting_semantics = {
        "hop_count_alias": "logical_hop_count",
        "logical_hop_count_description": "total TTL/path positions, including silent hops",
        "responding_hop_count_description": "hops that returned an IP/ICMP response",
        "silent_hop_count_description": "logical hops without ICMP response",
        "edge_count_description": "transitions between logical consecutive hop positions",
    }

    asn_items: list[dict[str, Any]] = []
    hops_with_confirmed_asn = 0
    hops_with_public_prefix_asn = 0
    hops_without_asn = 0
    private_ip_hops = 0
    icmp_silent_hops = 0
    for node in trace_nodes:
        hop_index = int(node.get("hop") or 0)
        hop_ip = _normalize_ip(node.get("ip"))
        node_role = str(node.get("role") or "unknown")
        node_confidence = _confidence_to_float(node.get("confidence"))
        if not hop_ip:
            icmp_silent_hops += 1
            asn_items.append(
                {
                    "hop_id": node.get("id") or f"hop:unknown:{hop_index}",
                    "ip": None,
                    "hop_index": hop_index,
                    "attribution_state": "icmp_silent_no_ip",
                    "current_reason": "Hop silencioso sem IP observável para atribuição ASN.",
                    "future_resolution_method": "asn_correlation_by_public_prefix_traceroute",
                    "confidence": 0.0,
                    "operator_message": "Não coletável ainda; o hop não respondeu e não há IP para atribuição ASN.",
                }
            )
            continue
        is_private = ipaddress.ip_address(hop_ip).is_private
        summary_row = rows_by_ip.get(hop_ip)
        row_asn = summary_row.get("asn") if isinstance(summary_row, dict) else None
        row_confidence = str(summary_row.get("confidence") or node.get("confidence") or "unknown") if isinstance(summary_row, dict) else str(node.get("confidence") or "unknown")
        row_org = summary_row.get("organization") if isinstance(summary_row, dict) else None
        if is_private:
            private_ip_hops += 1
            asn_items.append(
                {
                    "hop_id": node.get("id") or f"hop:{hop_ip}",
                    "ip": hop_ip,
                    "hop_index": hop_index,
                    "attribution_state": "private_ip_not_publicly_attributable_now",
                    "current_reason": "IP privado observado; ASN não identificável agora.",
                    "future_resolution_method": "asn_correlation_by_public_prefix_traceroute",
                    "confidence": 0.0,
                    "operator_message": "ASN não identificável agora; hop privado aguardando o motor futuro de atribuição ASN por correlação.",
                }
            )
            continue
        if row_asn is None:
            hops_without_asn += 1
            asn_items.append(
                {
                    "hop_id": node.get("id") or f"hop:{hop_ip}",
                    "ip": hop_ip,
                    "hop_index": hop_index,
                    "attribution_state": "awaiting_future_asn_correlation_engine" if hop_index != path_length else "missing_asn",
                    "current_reason": "Hop público observado, mas sem ASN local confiável.",
                    "future_resolution_method": "asn_correlation_by_public_prefix_traceroute",
                    "confidence": min(max(float(node_confidence) * 0.4, 0.0), 0.4),
                    "operator_message": "ASN não identificável agora; aguardando motor futuro de atribuição ASN por correlação.",
                }
            )
            continue
        if row_confidence == "confirmed":
            hops_with_confirmed_asn += 1
            attribution_state = "confirmed_asn"
            confidence_value = 0.95
            current_reason = "ASN confirmado na visão local persistida."
        else:
            hops_with_public_prefix_asn += 1
            attribution_state = "public_prefix_asn_only"
            confidence_value = 0.6
            current_reason = "ASN visível apenas por prefixo público, não como posse confirmada do roteador."
        asn_items.append(
            {
                "hop_id": node.get("id") or f"hop:{hop_ip}",
                "ip": hop_ip,
                "hop_index": hop_index,
                "attribution_state": attribution_state,
                "current_reason": current_reason,
                "future_resolution_method": "asn_correlation_by_public_prefix_traceroute",
                "confidence": confidence_value,
                "operator_message": "ASN observado sem forçar posse do roteador; a atribuição fina permanece limitada.",
                "asn": row_asn,
                "asn_name": row_org,
            }
        )

    remaining_ignorance = [
        {
            "type": "missing_asn",
            "severity": "normal",
            "reason": "Dois hops públicos do caminho ainda não possuem ASN local confiável.",
            "suggested_next_action": "aguardar motor futuro de atribuição ASN por correlação",
            "requires_active_action": False,
            "can_learn_in_background": False,
            "planned_future_engine": "asn_correlation_by_public_prefix_traceroute",
            "operator_message": "ASN não identificável agora; manter a lacuna explícita até o futuro motor por correlação.",
        },
        {
            "type": "missing_reverse_dns",
            "severity": "low",
            "reason": "A leitura atual ainda não consolidou reverse DNS confiável para todos os hops relevantes.",
            "suggested_next_action": "lookup_reverse_dns_if_public",
            "requires_active_action": False,
            "can_learn_in_background": True,
            "planned_future_engine": "reverse_dns_background_enrichment",
            "operator_message": "Reverse DNS segue incompleto; não inventar hostname onde não houve persistência.",
        },
        {
            "type": "icmp_silent_hops",
            "severity": "normal",
            "reason": "Há hops sem resposta explícita no traceroute, então parte da sequência ainda é inferida por continuidade.",
            "suggested_next_action": "preservar lacuna e revisar com futuras medições",
            "requires_active_action": False,
            "can_learn_in_background": True,
            "planned_future_engine": "future_trace_alignment_engine",
            "operator_message": "ICMP silencioso continua sendo uma lacuna real; não transformar silêncio em certeza.",
        },
        {
            "type": "private_hop_no_public_rdap",
            "severity": "normal",
            "reason": "Hops privados não são publicamente atribuíveis agora e não devem receber ASN forçado.",
            "suggested_next_action": "aguardar motor futuro de atribuição ASN por correlação",
            "requires_active_action": False,
            "can_learn_in_background": False,
            "planned_future_engine": "asn_correlation_by_public_prefix_traceroute",
            "operator_message": "Hop privado marcado como ASN não identificável agora; a atribuição por correlação virá depois da finalização visual.",
        },
        {
            "type": "final_destination_not_asserted",
            "severity": "low",
            "reason": "A rota alcançou o destino, mas o perfil ainda não converte reachability em assertiva final.",
            "suggested_next_action": "manter evidência de chegada sem reescrever a regra de assertiva final",
            "requires_active_action": False,
            "can_learn_in_background": True,
            "planned_future_engine": "route_profile_finalization_review",
            "operator_message": "O destino foi observado no traceroute, mas o perfil ainda preserva a cautela operacional sobre a assertiva final.",
        },
        {
            "type": "awaiting_future_asn_correlation_engine",
            "severity": "high",
            "reason": "A leitura atual já mostra onde o ASN falta, mas ainda não existe motor de correlação dedicado para fechar os buracos.",
            "suggested_next_action": "aguardar motor futuro de atribuição ASN por correlação",
            "requires_active_action": False,
            "can_learn_in_background": False,
            "planned_future_engine": "asn_correlation_by_public_prefix_traceroute",
            "operator_message": "Alguns hops foram observados, mas ainda não possuem ASN atribuído com confiança. Eles serão candidatos ao futuro motor de atribuição ASN por correlação, baseado em traceroutes orientados por prefixos anunciados publicamente.",
        },
    ]

    measurement_context_status = "historical_pre_change_baseline"
    baseline_type = "pre_local_network_change"
    context_note = "This profile was captured before the local NAT reduction and IPv6 enablement."
    if dedicated_trace_evidence and _is_cloudflare_dedicated_trace_plan(route_learning.get("plan_uid")):
        baseline_type = "post_local_network_change"
        measurement_context_status = "post_change_baseline"
        context_note = "This profile was captured after the local NAT reduction and IPv6 enablement."

    route_profile = {
        "profile_uid": profile_uid,
        "service": service_slug,
        "target": target_value,
        "profile_type": "dedicated_trace_profile",
        "status": "active_profile_partial" if dedicated_trace_evidence else "partial",
        "learned_from": {
            "dedicated_run_uid": dedicated_run_uid,
            "execution_type": "dedicated_trace_run" if dedicated_trace_evidence else "shared_service_hops_only",
            "plan_uid": route_learning.get("plan_uid") if isinstance(route_learning, dict) else None,
            "source": "external_route_inventory.external_route_traceroute_runs",
        },
        "generated_at": generated_at,
        "last_observed_at": last_observed_at,
        "evidence": {
            "source": [
                "external_route_inventory.external_route_traceroute_runs",
                "external_route_inventory.external_route_hop_edges",
                "routegraph/service/cloudflare",
                "routegraph/service/google",
            ],
            "dedicated_run_uid": dedicated_run_uid,
            "persisted": bool(dedicated_trace_evidence),
            "execution_type": "dedicated_trace_run" if dedicated_trace_evidence else "shared_service_hops_only",
            "ping_status": "SUCCESS" if dedicated_trace_evidence else "unknown",
            "traceroute_status": "SUCCESS" if dedicated_trace_evidence else "unknown",
            "final_destination_asserted": False,
            "graph_available": bool(trace_nodes and trace_edges),
        },
        "route_summary": {
            "hop_count": len(trace_nodes),
            "logical_hop_count": len(trace_nodes),
            "responding_hop_count": int(latest_trace_run.get("hop_count") or 0) or None,
            "silent_hop_count": silent_hop_count,
            "private_hop_count": private_hop_count,
            "public_hop_count": public_hop_count,
            "persisted_edge_count": len(trace_edges),
            "edge_count": len(trace_edges),
            "ping_status": "SUCCESS" if dedicated_trace_evidence else "unknown",
            "traceroute_status": "SUCCESS" if dedicated_trace_evidence else "unknown",
            "final_destination_asserted": False,
            "has_dedicated_edges": bool(trace_edges),
            "common_trunk_with_google": "detected" if shared_examples or shared_comparison.get("shared_examples") else "not_detected",
            "branch_point": "to_be_verified" if dedicated_trace_evidence else "to_be_discovered",
            "confidence": "partial",
            "observed_graph_hop_count": len(trace_nodes),
            "observed_graph_edge_count": len(trace_edges),
            "run_record_hop_count": int(latest_trace_run.get("hop_count") or 0) or None,
        },
        "path_signature": {
            "first_hop": first_hop,
            "last_observed_hop": last_observed_hop,
            "public_hop_count": public_hop_count,
            "private_hop_count": private_hop_count,
            "silent_hop_count": silent_hop_count,
            "logical_hop_count": len(trace_nodes),
            "responding_hop_count": int(latest_trace_run.get("hop_count") or 0) or None,
            "hop_fingerprint": hop_fingerprint,
            "edge_fingerprint": edge_fingerprint,
            "path_length": path_length,
            "evidence_source": "external_route_inventory.external_route_traceroute_runs",
        },
        "confidence": "partial",
        "counting_semantics": counting_semantics,
        "limitations": list(
            dict.fromkeys(
                [
                    "missing_asn",
                    "missing_reverse_dns",
                    "icmp_silent_hops",
                    "private_hop_no_public_rdap",
                    "final_destination_assertion_limited",
                ]
            )
        ),
        "remaining_ignorance": remaining_ignorance,
        "asn_attribution_status": {
            "total_hops": len(trace_nodes),
            "hops_with_confirmed_asn": hops_with_confirmed_asn,
            "hops_with_public_prefix_asn": hops_with_public_prefix_asn,
            "hops_without_asn": hops_without_asn,
            "private_ip_hops": private_ip_hops,
            "icmp_silent_hops": icmp_silent_hops,
            "public_hop_count": public_hop_count,
            "logical_hop_count": len(trace_nodes),
            "responding_hop_count": int(latest_trace_run.get("hop_count") or 0) or None,
            "silent_hop_count": silent_hop_count,
            "attribution_engine_required": True,
            "attribution_engine_status": "waiting_future_correlation_engine",
            "operator_message": "Alguns hops foram observados, mas ainda não possuem ASN atribuído com confiança. Eles serão candidatos ao futuro motor de atribuição ASN por correlação, baseado em traceroutes orientados por prefixos anunciados publicamente.",
            "items": asn_items,
        },
        "reuse_policy": {
            "reusable_for_questions": True,
            "valid_for_service": service_slug,
            "valid_for_target": target_value,
            "can_answer_current_route": True,
            "can_answer_historical_change": False,
            "can_answer_asn_ownership_for_all_hops": False,
            "should_refresh_when": [
                "new_dedicated_run_exists",
                "route_change_detected",
                "operator_requests_refresh",
                "stale_after_hours",
                "future_asn_correlation_engine_updates_hops",
            ],
            "stale_after_hours": 72,
            "operator_message": "Este perfil pode responder perguntas sobre a rota observada para Cloudflare, mas deve ser atualizado se houver mudança de rota, nova medição dedicada ou quando o futuro motor de atribuição ASN enriquecer os hops.",
        },
        "comparison_policy": {
            "compare_against": "google_8.8.8.8" if (shared_examples or shared_comparison.get("shared_examples")) else None,
            "compare_against_previous_cloudflare_profile": False,
            "future_comparisons": [
                "cloudflare_profile_over_time",
                "google_vs_cloudflare_common_trunk",
                "before_after_route_change",
                "route_after_bgp_policy_change",
                "before_after_asn_correlation_enrichment",
            ],
            "operator_message": "A comparação com histórico Cloudflare precisa de novas runs futuras e a atribuição ASN completa virá em fase posterior.",
        },
        "temporal_comparison": {
            "status": "compared" if dedicated_run_count > 1 else "baseline_missing",
            "endpoint": "/route-learning/sessions/demo/cloudflare/temporal-comparison",
            "baseline_availability": {
                "status": "available" if dedicated_run_count > 1 else "missing",
                "reason": "previous_dedicated_route_profile_found" if dedicated_run_count > 1 else "no_previous_dedicated_route_profile",
            },
            "operator_message": "Comparação temporal real disponível." if dedicated_run_count > 1 else "Ainda não há baseline anterior dedicado; a run atual vira baseline inicial para futuras comparações.",
        },
        "measurement_context": {
            "baseline_type": baseline_type,
            "local_change_event": "nat_reduced_ipv6_enabled",
            "local_change_event_at": "2026-06-11",
            "ip_family": "ipv4",
            "target": target_value,
            "context_note": context_note,
            "measurement_context_status": measurement_context_status,
        },
        "operator_message": "Perfil operacional Cloudflare aprendido com run dedicada persistida; ASN privado ou ausente continua explicitamente sem forçar atribuição.",
        "metadata": {
            "demo_mode": True,
            "read_only": True,
            "builder_mode": "route_profile",
            "builder_version": "v1-dedicated-profile",
            "route_learning": {
                "execution_type": "dedicated_trace_run" if dedicated_trace_evidence else "shared_service_hops_only",
                "dedicated_run_uid": dedicated_run_uid,
                "plan_uid": route_learning.get("plan_uid") if isinstance(route_learning, dict) else None,
            },
            "routegraph_service": service_slug,
            "routegraph_demo": True,
            "created_from": "existing_routegraph_and_external_route_inventory",
            "common_trunk_with_google": bool(shared_examples or shared_comparison.get("shared_examples")),
            "shared_examples_count": len(shared_examples or shared_comparison.get("shared_examples") or []),
            "observed_graph_nodes": len(trace_nodes),
            "observed_graph_edges": len(trace_edges),
        },
    }
    return route_profile


def _build_route_profile_summary(route_profile: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(route_profile, dict):
        return {}
    asn_status = route_profile.get("asn_attribution_status") if isinstance(route_profile.get("asn_attribution_status"), dict) else {}
    learned_from = route_profile.get("learned_from") if isinstance(route_profile.get("learned_from"), dict) else {}
    route_summary = route_profile.get("route_summary") if isinstance(route_profile.get("route_summary"), dict) else {}
    return {
        "profile_uid": route_profile.get("profile_uid"),
        "status": route_profile.get("status"),
        "endpoint": "/route-learning/sessions/demo/cloudflare/route-profile",
        "learned_from": {
            "dedicated_run_uid": learned_from.get("dedicated_run_uid"),
            "execution_type": learned_from.get("execution_type"),
            "plan_uid": learned_from.get("plan_uid"),
        },
        "confidence": route_profile.get("confidence"),
        "route_summary": route_summary,
        "counting_semantics": route_profile.get("counting_semantics") if isinstance(route_profile.get("counting_semantics"), dict) else None,
        "asn_attribution_summary": {
            "total_hops": asn_status.get("total_hops"),
            "hops_without_asn": asn_status.get("hops_without_asn"),
            "private_ip_hops": asn_status.get("private_ip_hops"),
            "icmp_silent_hops": asn_status.get("icmp_silent_hops"),
            "logical_hop_count": asn_status.get("logical_hop_count"),
            "responding_hop_count": asn_status.get("responding_hop_count"),
            "silent_hop_count": asn_status.get("silent_hop_count"),
            "public_hop_count": asn_status.get("public_hop_count"),
            "attribution_engine_status": asn_status.get("attribution_engine_status"),
        },
        "measurement_context": route_profile.get("measurement_context") if isinstance(route_profile.get("measurement_context"), dict) else None,
        "temporal_comparison": route_profile.get("temporal_comparison") if isinstance(route_profile.get("temporal_comparison"), dict) else None,
        "operator_message": route_profile.get("operator_message"),
    }


def _build_learning_comparison_plan(
    *,
    service: str,
    target: str | None = None,
    dedicated_run_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    service_slug = _normalize_service(service)
    normalized_target = _normalize_ip(target) or str(target).strip() if target else "cloudflare"
    if service_slug != _CLOUDFLARE_SERVICE:
        return {
            "comparison_uid": f"cmp-{_safe_uid_fragment(service_slug)}-unsupported",
            "status": "partial",
            "service": service_slug,
            "target": normalized_target,
            "learning_comparison_plan": None,
            "limitations": ["unsupported_comparison_plan"],
            "operator_message": "Comparador planejado disponível apenas para Cloudflare nesta rodada.",
            "active_action_executed": False,
            "metadata": {"demo_mode": True, "builder_mode": "comparison_plan", "unsupported": True},
        }

    cloudflare_payload = _build_cloudflare_shared_payload_base("cloudflare", service_slug)
    state = _cloudflare_dedicated_trace_state(service_slug)
    dedicated_run_plan = dedicated_run_plan or cloudflare_payload.get("dedicated_run_plan") or _build_cloudflare_dedicated_run_plan()
    if state.get("dedicated_trace_evidence"):
        dedicated_run_plan = copy.deepcopy(dedicated_run_plan)
        dedicated_run_plan["status"] = "executed"
        dedicated_run_plan["active_action_executed"] = True
        dedicated_run_plan["reason"] = "run_dedicada_persistida_em_externo_route_inventory"
        dedicated_run_plan["revealed_by"] = "route_learning_cloudflare_dedicated_trace_run"
        dedicated_run_plan["operator_message"] = "Run dedicada Cloudflare detectada e persistida no inventario externo; este bloco e read-only e nao executa nova medicao."
        dedicated_run_plan.setdefault("metadata", {})
        dedicated_run_plan["metadata"].update(
            {
                "dedicated_run_uid": state.get("dedicated_run_uid"),
                "route_learning": state.get("route_learning"),
                "dedicated_trace_evidence": True,
            }
        )
    before_limitations = [
        "shared_service_hops_only",
        "no_dedicated_trace_run",
        "no_cloudflare_edges_persisted",
        "no_destination_final_hop_asserted",
    ]
    before_state = {
        "status": cloudflare_payload.get("status"),
        "evidence_type": "shared_service_hops_only",
        "has_dedicated_trace_run": False,
        "has_cloudflare_edges": False,
        "final_destination_asserted": False,
        "common_trunk_with_google": "detected",
        "confidence": "partial",
        "known_nodes_count": len(cloudflare_payload.get("nodes") or []),
        "known_edges_count": len(cloudflare_payload.get("edges") or []),
        "ignorance_events_count": len(cloudflare_payload.get("ignorance_events") or []),
        "learning_queue_count": len(cloudflare_payload.get("learning_queue") or []),
        "limitations": before_limitations,
    }
    observed_after_state = {
        "exists": bool(state.get("dedicated_trace_evidence")),
        "dedicated_run_uid": state.get("dedicated_run_uid"),
        "evidence_type": "dedicated_trace_evidence" if state.get("dedicated_trace_evidence") else None,
        "has_dedicated_trace_run": bool(state.get("dedicated_trace_evidence")),
        "has_cloudflare_edges": bool(state.get("dedicated_graph_edges")),
        "final_destination_asserted": bool(state.get("final_destination_asserted")),
        "common_trunk_with_google": "detected" if state.get("shared_examples") else "not_detected",
        "branch_point": "to_be_discovered" if not state.get("dedicated_trace_evidence") else "to_be_verified",
        "confidence": "partial" if not state.get("dedicated_trace_evidence") else ("confirmed" if state.get("final_destination_asserted") else "partial"),
        "limitations_remaining": state.get("limitations_remaining") or [],
    }
    comparison_result = {
        "status": "observed" if observed_after_state["exists"] else "planned",
        "compared_at": _now().isoformat(),
        "dimensions": [
            {
                "name": "dedicated_edges_vs_shared_edges",
                "before": before_state["known_edges_count"],
                "after": len(state.get("dedicated_graph_edges") or []),
                "delta": len(state.get("dedicated_graph_edges") or []) - before_state["known_edges_count"],
            },
            {
                "name": "common_trunk_google_vs_cloudflare",
                "before": before_state["common_trunk_with_google"],
                "after": observed_after_state["common_trunk_with_google"],
            },
            {
                "name": "confidence_delta",
                "before": before_state["confidence"],
                "after": observed_after_state["confidence"],
            },
        ],
        "knowledge_gain_observed": [
            "dedicated_trace_evidence" if observed_after_state["exists"] else "pending_dedicated_run_confirmation",
        ],
        "limitations": observed_after_state["limitations_remaining"],
        "operator_message": "Comparação observada disponível com evidência dedicada persistida." if observed_after_state["exists"] else "Comparação ainda planejada; falta a run dedicada confirmada.",
    }
    after_state_expected = {
        "status": "expected_after_dedicated_run",
        "evidence_type": "dedicated_trace_evidence_expected",
        "has_dedicated_trace_run": "expected",
        "has_cloudflare_edges": "expected",
        "final_destination_assertion": "to_be_verified",
        "common_trunk_with_google": "to_be_compared",
        "branch_point": "to_be_discovered",
        "confidence": "to_be_recalculated",
        "limitations_expected_to_clear": [
            "shared_service_hops_only",
            "no_dedicated_trace_run",
            "no_cloudflare_edges_persisted",
        ],
        "limitations_that_may_remain": [
            "private_hop_no_public_rdap",
            "missing_asn",
            "missing_reverse_dns",
            "icmp_silent_hops",
        ],
    }
    comparable_dimensions = [
        {
            "name": "dedicated_edges_vs_shared_edges",
            "before_available": False,
            "after_required": True,
            "comparison_method": "compare edge count and transition sequence after dedicated trace",
            "operator_message": "Depois da run dedicada, comparar edges próprias contra a sequência compartilhada atual.",
        },
        {
            "name": "common_trunk_google_vs_cloudflare",
            "before_available": "detected",
            "after_required": True,
            "comparison_method": "compare shared trunk before and after dedicated evidence",
            "operator_message": "Confirmar ou negar o tronco comum com Google após a medição dedicada.",
        },
        {
            "name": "branch_point",
            "before_available": False,
            "after_required": True,
            "comparison_method": "inspect first divergence between shared and dedicated path",
            "operator_message": "Localizar onde Cloudflare se separa do tronco compartilhado.",
        },
        {
            "name": "hop_count_delta",
            "before_available": True,
            "after_required": True,
            "comparison_method": "compare node counts before and after dedicated evidence",
            "operator_message": "Medir quantos hops novos a run dedicada revelou.",
        },
        {
            "name": "private_hop_overlap",
            "before_available": True,
            "after_required": True,
            "comparison_method": "compare private hop sets and overlap reduction/growth",
            "operator_message": "Ver se o caminho dedicado reutiliza ou rompe hops privados atuais.",
        },
        {
            "name": "public_hop_overlap",
            "before_available": False,
            "after_required": True,
            "comparison_method": "compare public hops and edge emergence",
            "operator_message": "Ver quais hops públicos passaram a ser próprios da Cloudflare.",
        },
        {
            "name": "unknown_hops_delta",
            "before_available": True,
            "after_required": True,
            "comparison_method": "compare unknown hop counts and unresolved gaps",
            "operator_message": "Quantificar o quanto a run dedicada reduziu a ignorância explícita.",
        },
        {
            "name": "missing_asn_delta",
            "before_available": True,
            "after_required": True,
            "comparison_method": "compare unresolved ASN counts before and after",
            "operator_message": "Ver quantos haves de ASN deixam de faltar após a run dedicada.",
        },
        {
            "name": "missing_reverse_dns_delta",
            "before_available": True,
            "after_required": True,
            "comparison_method": "compare reverse DNS gaps before and after",
            "operator_message": "Medir se a rota dedicada melhora a leitura de reverse DNS.",
        },
        {
            "name": "confidence_delta",
            "before_available": True,
            "after_required": True,
            "comparison_method": "compare confidence levels across matched nodes and edges",
            "operator_message": "Recalcular confiança com evidência dedicada, não com compartilhamento.",
        },
        {
            "name": "route_profile_change",
            "before_available": False,
            "after_required": True,
            "comparison_method": "compare current partial profile against future dedicated profile",
            "operator_message": "Preparar o futuro route profile Cloudflare após a run dedicada.",
        },
        {
            "name": "destination_reachability_evidence",
            "before_available": False,
            "after_required": True,
            "comparison_method": "compare final hop and destination assertion evidence",
            "operator_message": "Confirmar se o destino final pode ou não ser afirmado depois da run.",
        },
    ]
    expected_knowledge_gain = [
        {"name": "substitute_shared_inference_with_dedicated_evidence", "expected": True, "observed": False, "depends_on": "dedicated_run_confirmation"},
        {"name": "confirm_or_reject_common_trunk_with_google", "expected": True, "observed": False, "depends_on": "dedicated_run_confirmation"},
        {"name": "discover_real_branch_point", "expected": True, "observed": False, "depends_on": "dedicated_run_confirmation"},
        {"name": "create_cloudflare_owned_edges", "expected": True, "observed": False, "depends_on": "dedicated_run_confirmation"},
        {"name": "reduce_no_dedicated_trace_run_gap", "expected": True, "observed": False, "depends_on": "dedicated_run_confirmation"},
        {"name": "improve_destination_confidence", "expected": True, "observed": False, "depends_on": "dedicated_run_confirmation"},
        {"name": "feed_future_cloudflare_route_profile", "expected": True, "observed": False, "depends_on": "dedicated_run_confirmation"},
    ]
    plan_uid = f"cmp-cloudflare-dedicated-trace-v1"
    comparison_status = "observed_after_dedicated_run" if observed_after_state["exists"] else "waiting_for_dedicated_run"
    return {
        "comparison_uid": plan_uid,
        "status": comparison_status,
        "service": service_slug,
        "target": normalized_target,
        "before_state": before_state,
        "after_state_expected": after_state_expected,
        "observed_after_state": observed_after_state,
        "comparable_dimensions": comparable_dimensions,
        "unknowns_to_resolve": [
            "exact_cloudflare_branch_point",
            "whether_google_shared_trunk_is_confirmed_or_refuted",
            "true_destination_final_hop",
            "dedicated_cloudflare_edge_sequence",
        ],
        "expected_knowledge_gain": expected_knowledge_gain,
        "comparison_result": comparison_result,
        "evidence_requirements": {
            "requires_operator_confirmation": True,
            "required_role": "admin",
            "must_use_dedicated_trace_evidence": True,
            "must_not_rely_on_shared_service_hops_only": True,
        },
        "safety_policy": {
            "read_only_plan": True,
            "no_execution_in_this_request": True,
            "require_admin": True,
            "require_confirm": True,
            "no_database_write": True,
            "no_active_measurement": True,
            "no_ping": True,
            "no_traceroute": True,
            "no_mikrotik_collection": True,
            "no_external_enrichment": True,
            "no_bgp_cursor_change": True,
        },
        "operator_message": "Antes da medição dedicada, eu só inferia Cloudflare por hops compartilhados. Depois de uma run dedicada confirmada, eu posso comparar o que foi aprendido." if not observed_after_state["exists"] else "Comparação observada: Cloudflare já tem run dedicada persistida e agora o aprendizado pode ser comparado contra a inferência compartilhada.",
        "active_action_executed": False,
        "limitations": [
            "shared_service_hops_only",
            "no_dedicated_trace_run",
            "no_cloudflare_edges_persisted",
            "no_destination_final_hop_asserted",
        ],
        "metadata": {
            "demo_mode": True,
            "builder_mode": "learning_comparison_plan",
            "source_refs": ["routegraph/service/cloudflare", "routegraph/service/google", "external_route_inventory/shared_service_hops"],
            "dedicated_run_plan_uid": dedicated_run_plan.get("plan_uid"),
            "before_state_summary": before_state,
            "observed_after_state": observed_after_state,
            "comparison_result": comparison_result,
        },
    }


def build_learning_comparison_plan(service: str, target: str | None = None) -> dict[str, Any]:
    normalized_target = _normalize_ip(target) or str(target).strip() if target else "cloudflare"
    return _build_learning_comparison_plan(service=service, target=normalized_target)


def build_cloudflare_post_change_run_plans() -> dict[str, Any]:
    return _build_cloudflare_post_change_run_plans()


def build_route_profile(service: str, target: str | None = None) -> dict[str, Any]:
    service_slug = _normalize_service(service)
    normalized_target = _normalize_ip(target) or str(target).strip() if target else "cloudflare"
    if service_slug != _CLOUDFLARE_SERVICE:
        return {
            "profile_uid": f"profile-{_safe_uid_fragment(service_slug)}-unsupported",
            "service": service_slug,
            "target": normalized_target,
            "profile_type": "dedicated_trace_profile",
            "status": "partial",
            "learned_from": None,
            "generated_at": _now().isoformat(),
            "last_observed_at": None,
            "evidence": None,
            "route_summary": None,
            "path_signature": None,
            "confidence": "partial",
            "limitations": ["unsupported_route_profile"],
            "remaining_ignorance": [],
            "asn_attribution_status": {
                "total_hops": 0,
                "hops_with_confirmed_asn": 0,
                "hops_with_public_prefix_asn": 0,
                "hops_without_asn": 0,
                "private_ip_hops": 0,
                "icmp_silent_hops": 0,
                "attribution_engine_required": False,
                "attribution_engine_status": "unsupported_route_profile",
                "operator_message": "Perfil de rota disponível apenas para Cloudflare nesta rodada.",
                "items": [],
            },
            "reuse_policy": {
                "reusable_for_questions": False,
                "valid_for_service": service_slug,
                "valid_for_target": normalized_target,
                "can_answer_current_route": False,
                "can_answer_historical_change": False,
                "can_answer_asn_ownership_for_all_hops": False,
                "should_refresh_when": [],
                "stale_after_hours": None,
                "operator_message": "Perfil de rota indisponível para este serviço nesta rodada.",
            },
            "comparison_policy": {
                "compare_against": None,
                "compare_against_previous_cloudflare_profile": False,
                "future_comparisons": [],
                "operator_message": "Comparação não suportada para este serviço nesta rodada.",
            },
            "operator_message": "Perfil de rota parcial não suportado para este serviço nesta rodada.",
            "metadata": {"demo_mode": True, "builder_mode": "route_profile", "unsupported": True},
        }
    return _cloudflare_route_profile_state(service_slug)


def _build_shared_tree(target: str, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    hop_nodes = [node for node in nodes if node.get("node_type") == "hop"]
    return {
        "tree_uid": f"tree-demo-{_safe_uid_fragment(target)}-shared-builder",
        "root_node_id": "origin:local",
        "paths": [
            {
                "path_uid": f"path-demo-{_safe_uid_fragment(target)}-shared-builder",
                "target": target,
                "node_sequence": ["origin:local", *[node["id"] for node in hop_nodes]],
                "edge_sequence": [edge["id"] for edge in edges],
                "created_from": "external_route_inventory_shared_service_hops",
                "is_baseline": False,
            }
        ],
        "branches": [],
        "common_trunks": [
            {
                "trunk_uid": "trunk-google-cloudflare-shared-private",
                "node_sequence": ["origin:local", *[node["id"] for node in hop_nodes]],
                "targets": ["8.8.8.8", target],
                "description": "Tronco comum detectado por hops compartilhados persistidos entre google e cloudflare.",
            }
        ],
    }


def _summary_for_shared_payload(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    hop_nodes = [node for node in nodes if node.get("node_type") == "hop"]
    counts = Counter(str(node.get("knowledge_state") or "unknown") for node in hop_nodes)
    return {
        "total_steps": len(hop_nodes),
        "known_count": counts.get("known", 0),
        "observed_now_count": len(hop_nodes),
        "unknown_count": 1,
        "queued_count": counts.get("queued_for_inventory", 0),
        "enriching_count": 0,
        "learned_now_count": 0,
        "limited_count": len(edges),
        "suspected_failure_count": 0,
        "icmp_silent_forwarding_ok_count": 0,
        "branch_count": 0,
        "evidence_sources": [
            "routegraph/service/cloudflare",
            "routegraph/service/google",
            "external_route_inventory/shared_service_hops",
        ],
        "active_action_executed": False,
        "requires_consent_for_active_actions": True,
    }


def _build_cloudflare_shared_payload_base(target: str, service_slug: str) -> dict[str, Any]:
    service_graph = build_service_route_graph(service_slug)
    service_summary = get_service_route_summary(service_slug)
    comparison = compare_service_routes("google", service_slug).get("comparison") or {}
    shared_examples = comparison.get("shared_examples") or []
    if not shared_examples:
        return _unsupported_payload(target, service_slug, "missing_shared_service_hops")

    shared_rows = [example.get("b") or {} for example in shared_examples]
    shared_rows = sorted(shared_rows, key=lambda row: int(row.get("min_hop_number") or 999))
    nodes = [_build_origin_node()]
    for order, row in enumerate(shared_rows, start=1):
        nodes.append(_build_shared_cloudflare_node(row, order))
    edges = _build_cloudflare_shared_edges(nodes)
    steps = _build_shared_steps(nodes, service_slug)
    ignorance_events = _build_cloudflare_ignorance_events(nodes)
    learning_queue = _build_cloudflare_learning_queue(nodes)
    dedicated_run_plan = _build_cloudflare_dedicated_run_plan()
    timeline = _build_timeline(nodes, edges, steps, ignorance_events, learning_queue)
    tree = _build_shared_tree(target, nodes, edges)
    summary_payload = _summary_for_shared_payload(nodes, edges)

    payload = copy.deepcopy(get_route_learning_demo_payload())
    payload.update(
        {
            "session_uid": f"demo-route-learning-{_safe_uid_fragment(target)}-{service_slug}-shared-hops",
            "profile_uid": None,
            "session_type": "route_trace",
            "target": {
                "target_type": "service",
                "value": target,
                "resolved_ips": ["1.1.1.1"],
                "selected_ip": None,
                "label": "Rota parcial para Cloudflare",
                "importance": "normal",
            },
            "status": "partial",
            "generated_at": _now().isoformat(),
            "principle": _PRINCIPLE,
            "summary": summary_payload,
            "timeline": timeline,
            "nodes": nodes,
            "edges": edges,
            "steps": steps,
            "ignorance_events": ignorance_events,
            "learning_queue": learning_queue,
            "tree": tree,
            "dedicated_run_plan": dedicated_run_plan,
            "visual": {
                **payload.get("visual", {}),
                "renderer_target": "konva",
                "canvas_mode": "route_learning",
                "layout_hint": "left_to_right_tree",
                "animation_enabled": True,
                "show_learning_queue": True,
                "show_ignorance_events": True,
                "show_packet_animation": True,
                "show_confidence": True,
                "demo_mode": True,
                "builder_mode": "read_only_shared_hops",
            },
            "limitations": [
                "read_only_only",
                "no_active_measurement",
                "no_ping",
                "no_traceroute",
                "no_mikrotik_collection",
                "no_external_enrichment",
                "no_database_write",
                "shared_service_hops_only",
                "no_dedicated_trace_run",
                "no_cloudflare_edges_persisted",
                "no_destination_final_hop_asserted",
            ],
        }
    )
    payload.setdefault("metadata", {})
    payload["metadata"].update(
        {
            "demo_mode": True,
            "read_only": True,
            "builder_mode": "read_only_shared_hops",
            "builder_version": "v2-second-target",
            "source_refs": summary_payload["evidence_sources"],
            "routegraph_service": service_slug,
            "routegraph_demo": True,
            "created_from": "existing_routegraph_and_external_route_inventory",
            "shared_service_hops_only": True,
            "dedicated_trace_run": False,
            "cloudflare_service_nodes": len(service_graph.get("nodes") or []),
            "cloudflare_service_edges": len(service_graph.get("edges") or []),
            "cloudflare_targets": service_summary.get("targets") or [],
            "operator_message": "Evidência reaproveitada de hops compartilhados; não há run dedicada para este serviço.",
            "demo_visual_anchor": True,
            "dedicated_run_plan_uid": dedicated_run_plan["plan_uid"],
        }
    )
    return payload


def _build_cloudflare_shared_payload(target: str, service_slug: str) -> dict[str, Any]:
    payload = _build_cloudflare_shared_payload_base(target, service_slug)
    learning_comparison_plan = _build_learning_comparison_plan(
        service=service_slug,
        target=target,
        dedicated_run_plan=payload.get("dedicated_run_plan"),
    )
    payload["post_change_run_plans"] = _build_cloudflare_post_change_run_plans()
    route_profile = build_route_profile(service_slug, target)
    payload["learning_comparison_plan"] = {
        "comparison_uid": learning_comparison_plan["comparison_uid"],
        "status": learning_comparison_plan["status"],
        "endpoint": "/route-learning/sessions/demo/cloudflare/learning-comparison-plan",
        "operator_message": learning_comparison_plan["operator_message"],
    }
    payload["route_profile"] = _build_route_profile_summary(route_profile)
    payload.setdefault("metadata", {})
    payload["metadata"]["learning_comparison_plan_uid"] = learning_comparison_plan["comparison_uid"]
    payload["metadata"]["route_profile_uid"] = route_profile.get("profile_uid")
    return payload


def _build_cloudflare_dedicated_payload(target: str, service_slug: str) -> dict[str, Any]:
    state = _cloudflare_dedicated_trace_state(service_slug)
    dedicated_target = str(state.get("latest_trace_run", {}).get("target_resolved_ip") or "1.1.1.1")
    payload = _build_dynamic_payload(dedicated_target, service_slug)
    if payload.get("status") == "partial" and state.get("dedicated_trace_evidence"):
        payload["status"] = "partial"
    dedicated_run_plan = _build_cloudflare_dedicated_run_plan()
    if state.get("dedicated_trace_evidence"):
        dedicated_run_plan = copy.deepcopy(dedicated_run_plan)
        dedicated_run_plan["status"] = "executed"
        dedicated_run_plan["active_action_executed"] = True
        dedicated_run_plan["reason"] = "run_dedicada_persistida_em_externo_route_inventory"
        dedicated_run_plan["revealed_by"] = "route_learning_cloudflare_dedicated_trace_run"
        dedicated_run_plan.setdefault("metadata", {})
        dedicated_run_plan["metadata"].update(
            {
                "dedicated_run_uid": state.get("dedicated_run_uid"),
                "route_learning": state.get("route_learning"),
                "dedicated_trace_evidence": True,
            }
        )
    learning_comparison_plan = _build_learning_comparison_plan(
        service=service_slug,
        target=target,
        dedicated_run_plan=dedicated_run_plan,
    )
    payload["post_change_run_plans"] = _build_cloudflare_post_change_run_plans()
    route_profile = build_route_profile(service_slug, target)
    payload["target"] = {
        "target_type": "ip",
        "value": dedicated_target,
        "resolved_ips": [dedicated_target],
        "selected_ip": dedicated_target,
        "label": "Cloudflare dedicada",
        "importance": "normal",
    }
    payload["session_uid"] = f"demo-route-learning-{dedicated_target.replace('.', '-')}-{service_slug}-dedicated-trace"
    payload["status"] = "completed" if payload.get("summary", {}).get("limited_count") == 0 and payload.get("summary", {}).get("unknown_count") == 0 else "partial"
    payload["dedicated_run_plan"] = dedicated_run_plan
    payload["learning_comparison_plan"] = {
        "comparison_uid": learning_comparison_plan["comparison_uid"],
        "status": learning_comparison_plan["status"],
        "endpoint": "/route-learning/sessions/demo/cloudflare/learning-comparison-plan",
        "operator_message": learning_comparison_plan["operator_message"],
        "observed_after_state": learning_comparison_plan.get("metadata", {}).get("observed_after_state"),
        "comparison_result": learning_comparison_plan.get("metadata", {}).get("comparison_result"),
    }
    payload["route_profile"] = _build_route_profile_summary(route_profile)
    payload["summary"] = {
        **(payload.get("summary") or {}),
        "active_action_executed": bool(state.get("dedicated_trace_evidence")),
        "dedicated_trace_evidence": bool(state.get("dedicated_trace_evidence")),
        "dedicated_run_uid": state.get("dedicated_run_uid"),
        "remaining_limitations": state.get("limitations_remaining") or [],
    }
    limitations = list(dict.fromkeys([*(payload.get("limitations") or [])]))
    for limitation in [
        "read_only_only",
        "no_active_measurement",
        "no_ping",
        "no_traceroute",
        "no_database_write",
        "shared_service_hops_only",
        "no_dedicated_trace_run",
    ]:
        if limitation in limitations:
            limitations.remove(limitation)
    if "no_cloudflare_edges_persisted" in limitations and state.get("dedicated_graph_edges"):
        limitations.remove("no_cloudflare_edges_persisted")
    for limitation in state.get("limitations_remaining") or []:
        if limitation not in limitations:
            limitations.append(limitation)
    payload["limitations"] = limitations
    payload.setdefault("metadata", {})
    payload["metadata"].update(
        {
            "demo_mode": True,
            "read_only": True,
            "builder_mode": "dedicated_trace_payload",
            "routegraph_service": service_slug,
            "route_learning": {
                "execution_type": "dedicated_trace_run",
                "active_action_executed": bool(state.get("dedicated_trace_evidence")),
                "dedicated_run_uid": state.get("dedicated_run_uid"),
                "plan_uid": dedicated_run_plan.get("plan_uid"),
            },
            "dedicated_run_uid": state.get("dedicated_run_uid"),
            "learning_comparison_plan_uid": learning_comparison_plan["comparison_uid"],
            "route_profile_uid": route_profile.get("profile_uid"),
            "comparison_result": learning_comparison_plan.get("metadata", {}).get("comparison_result"),
            "operator_message": "Run dedicada Cloudflare detectada e persistida no inventário externo.",
        }
    )
    return payload


def _unsupported_payload(target: str, service_slug: str, limitation: str) -> dict[str, Any]:
    payload = copy.deepcopy(get_route_learning_demo_payload())
    payload["session_uid"] = f"demo-route-learning-{_safe_uid_fragment(target)}-{service_slug}-unsupported"
    payload["target"] = {
        "target_type": "ip",
        "value": target,
        "resolved_ips": [target] if target == _SUPPORTED_TARGET else [],
        "selected_ip": target if target == _SUPPORTED_TARGET else None,
        "label": _safe_target_label(target),
        "importance": "normal",
    }
    payload["status"] = "partial"
    payload["generated_at"] = _now().isoformat()
    payload["limitations"] = [limitation, "read_only_only", "no_active_measurement"]
    payload.setdefault("metadata", {})
    payload["metadata"].update(
        {
            "demo_mode": True,
            "builder_mode": "read_only_dynamic",
            "builder_limitation": limitation,
            "source_refs": ["routegraph/global", "routegraph/service/google"],
        }
    )
    return payload


def _build_dynamic_payload(target: str, service_slug: str) -> dict[str, Any]:
    service_graph = build_service_route_graph(service_slug)
    summary = get_service_route_summary(service_slug)
    trace_run = summary.get("latest_trace_run") or {}
    trace_uid = trace_run.get("run_uid")
    if not trace_uid:
        return _unsupported_payload(target, service_slug, "missing_persisted_trace_run")
    trace_graph = get_external_route_trace_graph(trace_uid)

    service_nodes_by_ip = _service_graph_node_map(service_graph)
    trace_nodes = _trace_nodes_by_hop(trace_graph)
    trace_edges = _trace_edges_by_hop(trace_graph)

    nodes: list[dict[str, Any]] = [_build_origin_node()]
    edges: list[dict[str, Any]] = [_build_demo_anchor_edge()]

    previous_ip: str | None = None
    for hop in sorted(trace_nodes):
        trace_node = trace_nodes[hop]
        ip = _normalize_ip(trace_node.get("ip"))
        service_node = service_nodes_by_ip.get(ip) if ip else None
        if ip is None:
            node = _build_unknown_hop_node(hop, previous_ip, _normalize_ip(trace_nodes.get(hop + 1, {}).get("ip")))
        else:
            node = _build_hop_node(hop=hop, trace_node=trace_node, service_node=service_node)
        nodes.append(node)
        previous_ip = ip

    for hop in sorted(trace_edges):
        edge = trace_edges[hop]
        from_ip = _normalize_ip(edge.get("from_hop_ip"))
        to_ip = _normalize_ip(edge.get("to_hop_ip"))
        from_hop = int(edge.get("from_hop_index") or hop)
        from_node_id = f"hop:{from_ip}" if from_ip else f"hop:unknown:{from_hop}"
        if to_ip is None:
            to_node_id = f"hop:unknown:{int(edge.get('to_hop_index') or from_hop + 1)}"
        else:
            to_node_id = f"hop:{to_ip}"
        edges.append(_build_edge(edge=edge, hop=from_hop, source_node_id=from_node_id, target_node_id=to_node_id))

    steps = _build_steps(nodes)
    ignorance_events = _build_ignorance_events(nodes)
    learning_queue = _build_learning_queue(nodes)
    timeline = _build_timeline(nodes, edges, steps, ignorance_events, learning_queue)
    tree = _build_tree(nodes, edges)
    summary_payload = _summary_for_nodes(nodes)

    payload = copy.deepcopy(get_route_learning_demo_payload())
    payload.update(
        {
            "session_uid": f"demo-route-learning-{target.replace('.', '-')}-{service_slug}-{trace_uid}",
            "profile_uid": None,
            "session_type": "route_trace",
            "target": {
                "target_type": "ip",
                "value": target,
                "resolved_ips": [target],
                "selected_ip": target,
                "label": _safe_target_label(target),
                "importance": "normal",
            },
            "status": "partial" if summary_payload["unknown_count"] or summary_payload["queued_count"] or summary_payload["limited_count"] else "completed",
            "generated_at": _now().isoformat(),
            "summary": summary_payload,
            "timeline": timeline,
            "nodes": nodes,
            "edges": edges,
            "steps": steps,
            "ignorance_events": ignorance_events,
            "learning_queue": learning_queue,
            "tree": tree,
            "visual": {
                **payload.get("visual", {}),
                "renderer_target": "konva",
                "canvas_mode": "route_learning",
                "layout_hint": "left_to_right_tree",
                "animation_enabled": True,
                "show_learning_queue": True,
                "show_ignorance_events": True,
                "show_packet_animation": True,
                "show_confidence": True,
                "demo_mode": True,
                "builder_mode": "read_only_dynamic",
            },
            "limitations": [
                "read_only_only",
                "no_active_measurement",
                "no_ping",
                "no_traceroute",
                "no_mikrotik_collection",
                "no_external_enrichment",
                "no_database_write",
                "route_learning_session_builder_dynamic",
            ],
        }
    )
    payload.setdefault("metadata", {})
    payload["metadata"].update(
        {
            "demo_mode": True,
            "builder_mode": "read_only_dynamic",
            "builder_version": "v1",
            "source_refs": summary_payload["evidence_sources"],
            "routegraph_service": service_slug,
            "routegraph_run_uid": trace_uid,
            "routegraph_demo": True,
            "created_from": "existing_routegraph_and_external_route_inventory",
            "demo_visual_anchor": True,
        }
    )
    return payload


def build_route_learning_visual_payload(target: str, service: str | None = None) -> dict[str, Any]:
    normalized_target = _normalize_ip(target) or str(target).strip()
    service_slug = _normalize_service(service)
    if normalized_target == _CLOUDFLARE_TARGET and service_slug == _CLOUDFLARE_SERVICE:
        try:
            state = _cloudflare_dedicated_trace_state(service_slug)
            if state.get("dedicated_trace_evidence"):
                return _build_cloudflare_dedicated_payload(normalized_target, service_slug)
            return _build_cloudflare_shared_payload(normalized_target, service_slug)
        except Exception:
            return _unsupported_payload(normalized_target, service_slug, "cloudflare_shared_payload_build_failed")
    if normalized_target != _SUPPORTED_TARGET:
        return _unsupported_payload(normalized_target, service_slug, "unsupported_demo_target")
    if service_slug != _SUPPORTED_SERVICE:
        return _unsupported_payload(normalized_target, service_slug, "unsupported_demo_service")
    try:
        return _build_dynamic_payload(normalized_target, service_slug)
    except Exception:
        payload = copy.deepcopy(get_route_learning_demo_payload())
        payload["session_uid"] = f"demo-route-learning-{normalized_target.replace('.', '-')}-{service_slug}-fallback"
        payload["target"] = {
            "target_type": "ip",
            "value": normalized_target,
            "resolved_ips": [normalized_target],
            "selected_ip": normalized_target,
            "label": _safe_target_label(normalized_target),
            "importance": "normal",
        }
        payload["status"] = "partial"
        payload["generated_at"] = _now().isoformat()
        payload["limitations"] = list(dict.fromkeys([*(payload.get("limitations") or []), "fallback_static_demo"]))
        payload.setdefault("metadata", {})
        payload["metadata"].update(
            {
                "demo_mode": True,
                "builder_mode": "fallback_static_demo",
                "source_refs": ["routegraph/global", "routegraph/service/google"],
                "routegraph_service": service_slug,
                "routegraph_demo": True,
                "created_from": "static_demo_fallback",
            }
        )
        return payload
