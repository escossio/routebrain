from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Any

from app.schemas.route_graph import RouteGraphV1
from app.services.external_route_inventory import get_external_hop_context
from app.services.bgp_operational_queries import lookup_bgp_by_ip


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _confidence_for_node(*, is_silent: bool, ip: str | None, is_destination: bool, asn: int | None) -> str:
    if is_silent:
        return "low"
    if is_destination:
        return "high" if ip else "partial"
    if ip and asn is not None:
        return "high"
    if ip:
        return "partial"
    return "unknown"


def _is_private_ip(ip_value: str | None) -> bool:
    if not ip_value:
        return False
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local)


def _ip_family(ip_value: str | None) -> str:
    if not ip_value:
        return "unknown"
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return "unknown"
    return "ipv6" if address.version == 6 else "ipv4"


def _normalize_ip_text(ip_value: str | None) -> str | None:
    if not ip_value:
        return None
    text = str(ip_value).strip()
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _confidence_for_missing_field(field_name: str, hop_index: int, ip: str | None) -> str:
    if field_name == "asn":
        return "low" if ip else "unknown"
    if field_name == "as_name":
        return "low" if ip else "unknown"
    if field_name == "latency_ms":
        return "partial" if ip else "unknown"
    return "unknown"


def _bgp_context_for_private_ip() -> dict[str, str]:
    return {
        "status": "private_ip_no_direct_bgp_attribution",
        "reason": "private_or_cgnat_ip",
    }


def _bgp_evidence_for_public_ip(ip: str | None) -> dict[str, Any] | None:
    normalized_ip = _normalize_ip_text(ip)
    if not normalized_ip or _is_private_ip(normalized_ip):
        return None
    bgp_row = lookup_bgp_by_ip(normalized_ip)
    if not isinstance(bgp_row, dict):
        return None
    matched_prefix = bgp_row.get("matched_prefix")
    origin_asn = bgp_row.get("origin_asn")
    if not matched_prefix or origin_asn is None:
        return None
    as_path = None
    sample_as_paths = bgp_row.get("sample_as_paths")
    if isinstance(sample_as_paths, list) and sample_as_paths:
        as_path = sample_as_paths[0]
    elif isinstance(bgp_row.get("current_routes"), list):
        for route in bgp_row.get("current_routes") or []:
            if isinstance(route, dict) and route.get("as_path"):
                as_path = str(route.get("as_path"))
                break
    return {
        "matched_prefix": str(matched_prefix),
        "origin_asn": int(origin_asn),
        "as_path": str(as_path) if as_path else None,
        "source": "bgp_current_routes_lpm",
        "lookup_ip": normalized_ip,
        "confidence": "lpm",
        "attribution_scope": "public_ip",
    }


def _node_diagnostics(route_graph: dict[str, Any]) -> dict[str, Any]:
    nodes = route_graph.get("nodes") if isinstance(route_graph.get("nodes"), list) else []
    warnings = route_graph.get("warnings") if isinstance(route_graph.get("warnings"), list) else []
    null_fields = {"asn": 0, "as_name": 0, "latency_ms": 0, "ip": 0, "evidence": 0}
    asn_count = latency_count = evidence_count = 0
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for key in ("asn", "as_name", "latency_ms", "ip"):
            if node.get(key) is None:
                null_fields[key] += 1
        if node.get("asn") is not None:
            asn_count += 1
        if node.get("latency_ms") is not None:
            latency_count += 1
        if node.get("evidence"):
            evidence_count += 1
        else:
            null_fields["evidence"] += 1
    warning_categories = {
        "missing_data": 0,
        "backend_available_not_used": 0,
        "contract_inconsistency": 0,
        "expected_behavior": 0,
    }
    for warning in warnings:
        text = str(warning).lower()
        if "sem resposta explícita" in text:
            warning_categories["expected_behavior"] += 1
        elif "sem asn" in text or "sem nome de as" in text or "sem latência" in text:
            warning_categories["missing_data"] += 1
        elif "edges de origem menor" in text:
            warning_categories["backend_available_not_used"] += 1
        else:
            warning_categories["contract_inconsistency"] += 1
    return {
        "total_nodes": len(nodes),
        "total_edges": len(route_graph.get("edges") or []),
        "null_fields": null_fields,
        "warnings_by_category": warning_categories,
        "asn_count": asn_count,
        "missing_asn_count": len(nodes) - asn_count,
        "latency_count": latency_count,
        "missing_latency_count": len(nodes) - latency_count,
        "evidence_count": evidence_count,
        "missing_evidence_count": len(nodes) - evidence_count,
    }


def build_route_graph_report(route_graph: dict[str, Any]) -> dict[str, Any]:
    diagnostics = _node_diagnostics(route_graph)
    nodes = route_graph.get("nodes") if isinstance(route_graph.get("nodes"), list) else []
    hop_rows: list[dict[str, Any]] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        hop_rows.append(
            {
                "hop_index": node.get("hop_index"),
                "id": node.get("id"),
                "kind": node.get("kind"),
                "ip": node.get("ip"),
                "latency_ms": node.get("latency_ms"),
                "is_private": node.get("is_private"),
                "is_silent": node.get("is_silent"),
                "is_destination": node.get("is_destination"),
                "asn": node.get("asn"),
                "as_name": node.get("as_name"),
                "confidence": node.get("confidence"),
                "evidence_count": len(node.get("evidence") or []),
                "badges": list(node.get("badges") or []),
            }
        )
    return {
        "schema_version": route_graph.get("schema_version"),
        "graph_uid": route_graph.get("graph_uid"),
        "run_uid": (route_graph.get("source") or {}).get("run_uid"),
        "target": (route_graph.get("source") or {}).get("target"),
        "ip_family": (route_graph.get("source") or {}).get("ip_family"),
        "generated_at": (route_graph.get("source") or {}).get("generated_at"),
        "total_nodes": diagnostics["total_nodes"],
        "total_edges": diagnostics["total_edges"],
        "logical_hop_count": (route_graph.get("summary") or {}).get("logical_hop_count"),
        "responding_hop_count": (route_graph.get("summary") or {}).get("responding_hop_count"),
        "silent_hop_count": (route_graph.get("summary") or {}).get("silent_hop_count"),
        "private_hop_count": (route_graph.get("summary") or {}).get("private_hop_count"),
        "public_hop_count": (route_graph.get("summary") or {}).get("public_hop_count"),
        "destination_reached": (route_graph.get("summary") or {}).get("destination_reached"),
        "confidence": (route_graph.get("summary") or {}).get("confidence"),
        "asn_count": diagnostics["asn_count"],
        "missing_asn_count": diagnostics["missing_asn_count"],
        "as_name_count": diagnostics["total_nodes"] - diagnostics["null_fields"]["as_name"],
        "missing_as_name_count": diagnostics["null_fields"]["as_name"],
        "latency_count": diagnostics["latency_count"],
        "missing_latency_count": diagnostics["missing_latency_count"],
        "evidence_count": diagnostics["evidence_count"],
        "missing_evidence_count": diagnostics["missing_evidence_count"],
        "warnings_total": len(route_graph.get("warnings") or []),
        "warnings": list(route_graph.get("warnings") or []),
        "warnings_by_category": diagnostics["warnings_by_category"],
        "hops": hop_rows,
    }


def build_route_graph_v1(source_payload: dict[str, Any]) -> dict[str, Any]:
    run_uid = str(source_payload.get("run_uid") or source_payload.get("measurement_id") or source_payload.get("id") or "unknown")
    hops = source_payload.get("hops") or []
    if not isinstance(hops, list):
        hops = []
    ordered_hops = sorted(
        [hop for hop in hops if isinstance(hop, dict)],
        key=lambda item: int(item.get("hop_index") or item.get("hop_number") or item.get("hop") or 0),
    )
    target_ip = source_payload.get("target")
    warnings: list[str] = list(source_payload.get("warnings") or [])
    source_nodes = source_payload.get("nodes") if isinstance(source_payload.get("nodes"), list) else []
    source_edges = source_payload.get("edges") if isinstance(source_payload.get("edges"), list) else []
    nodes: list[dict[str, Any]] = []
    for index, hop in enumerate(ordered_hops, start=1):
        hop_index = int(hop.get("hop_index") or hop.get("hop_number") or hop.get("hop") or index)
        ip = _normalize_ip_text(hop.get("ip") or hop.get("hop_ip"))
        is_silent = not bool(ip)
        source_role = str(hop.get("role") or hop.get("hop_role") or "").lower()
        is_destination = bool(hop.get("is_destination") or hop.get("destination") or hop.get("is_final_hop") or source_role == "destination")
        if target_ip and ip and str(ip) == str(target_ip):
            is_destination = True
        is_private = _is_private_ip(str(ip) if ip else None)
        asn = hop.get("asn")
        as_name = hop.get("as_name") or hop.get("organization") or hop.get("provider_name")
        if asn is not None:
            try:
                asn = int(asn)
            except (TypeError, ValueError):
                asn = None
        if asn is None and ip and not is_private:
            bgp_evidence = _bgp_evidence_for_public_ip(str(ip))
            if isinstance(bgp_evidence, dict):
                origin_asn = bgp_evidence.get("origin_asn")
                if origin_asn is not None:
                    asn = int(origin_asn)
        external_context = None
        if ip and not is_private:
            try:
                external_context = get_external_hop_context(str(ip))
            except Exception:
                external_context = None
        if isinstance(external_context, dict) and external_context.get("status") == "ok":
            hop_ctx = external_context.get("hop") if isinstance(external_context.get("hop"), dict) else {}
            classification = external_context.get("classification") if isinstance(external_context.get("classification"), dict) else {}
            if asn is None and hop_ctx.get("asn") is not None:
                try:
                    asn = int(hop_ctx.get("asn"))
                except (TypeError, ValueError):
                    asn = None
            if classification.get("role"):
                source_role = str(classification.get("role") or source_role).lower()
        if external_context and isinstance(external_context, dict):
            hop_ctx = external_context.get("hop") if isinstance(external_context.get("hop"), dict) else {}
            evidence = [
                {"source": "external_hop_context", "status": external_context.get("status"), "classification": external_context.get("classification") or {}, "hop_ip": hop_ctx.get("hop_ip"), "reverse_dns": hop_ctx.get("reverse_dns")}
            ]
        else:
            evidence = list(hop.get("evidence") or [])
        bgp_evidence = None
        bgp_context = None
        if ip and is_private:
            bgp_context = _bgp_context_for_private_ip()
        elif ip and not is_private:
            bgp_evidence = _bgp_evidence_for_public_ip(str(ip))
        latency_ms = hop.get("latency_ms")
        if latency_ms is None:
            latency_ms = hop.get("rtt_ms") or hop.get("rtt_avg_ms")
        if latency_ms is not None:
            try:
                latency_ms = float(latency_ms)
            except (TypeError, ValueError):
                warnings.append(f"hop {hop_index} tem latência inválida preservada como null.")
                latency_ms = None
        if asn is None and ip and not is_private and not external_context:
            warnings.append(f"hop {hop_index} público sem ASN disponível.")
        if as_name is None and ip and not is_private and not external_context:
            warnings.append(f"hop {hop_index} público sem nome de AS disponível.")
        if latency_ms is None and ip and not is_private:
            warnings.append(f"hop {hop_index} público sem latência disponível.")
        if is_destination and not ip:
            warnings.append(f"hop {hop_index} marcado como destino sem IP explícito.")
        node = {
            "id": f"hop-{hop_index}",
            "kind": "destination" if is_destination else "silent_hop" if is_silent else "private_hop" if is_private or source_role in {"private", "local_network", "local"} else "public_hop" if ip else "unknown",
            "hop_index": hop_index,
            "label": hop.get("label") or (str(ip) if ip else f"Hop {hop_index}"),
            "ip": str(ip) if ip else None,
            "asn": asn,
            "as_name": as_name,
            "latency_ms": latency_ms,
            "is_private": is_private,
            "is_silent": is_silent,
            "is_destination": is_destination,
            "confidence": "partial" if external_context and isinstance(external_context, dict) and external_context.get("status") == "ok" and asn is None and ip else _confidence_for_node(is_silent=is_silent, ip=str(ip) if ip else None, is_destination=is_destination, asn=asn),
            "badges": list(hop.get("badges") or []),
            "evidence": evidence,
        }
        if bgp_evidence is not None:
            node["bgp_evidence"] = bgp_evidence
        if bgp_context is not None:
            node["bgp_context"] = bgp_context
        if node["asn"] is None:
            node["confidence"] = _confidence_for_missing_field("asn", hop_index, node["ip"])
        if node["as_name"] is None and node["confidence"] == "high":
            node["confidence"] = "partial"
        nodes.append(node)
        if is_silent:
            warnings.append(f"hop {hop_index} sem resposta explícita.")
    if source_edges and len(source_edges) < max(len(nodes) - 1, 0):
        warnings.append("quantidade de edges de origem menor que a sequência lógica; contrato preservou edges sequenciais.")
    edges = []
    for left, right in zip(nodes, nodes[1:]):
        edges.append({"id": f"edge-{left['id']}-{right['id']}", "source": left["id"], "target": right["id"], "kind": "logical_next_hop", "confidence": "high" if left["confidence"] == "high" and right["confidence"] == "high" else "partial"})
    logical_count = len(nodes)
    responding_count = sum(1 for node in nodes if not node["is_silent"])
    silent_count = sum(1 for node in nodes if node["is_silent"])
    private_count = sum(1 for node in nodes if node["is_private"])
    public_count = sum(1 for node in nodes if not node["is_private"] and not node["is_silent"])
    destination_reached = any(node["is_destination"] for node in nodes)
    confidence = "high" if responding_count and silent_count == 0 else "partial" if responding_count else "low" if nodes else "unknown"
    graph_uid = hashlib.sha1(f"{run_uid}:{len(nodes)}:{len(edges)}".encode("utf-8")).hexdigest()[:16]
    return RouteGraphV1.model_validate(
        {
            "schema_version": "routegraph.v1",
            "graph_uid": f"rg-{graph_uid}",
            "source": {
                "run_uid": run_uid,
                "session_id": source_payload.get("session_id"),
                "target": source_payload.get("target"),
                "ip_family": source_payload.get("ip_family") or _ip_family(source_payload.get("target")),
                "generated_at": source_payload.get("generated_at") or _now(),
            },
            "summary": {
                "logical_hop_count": logical_count,
                "responding_hop_count": responding_count,
                "silent_hop_count": silent_count,
                "private_hop_count": private_count,
                "public_hop_count": public_count,
                "destination_reached": destination_reached,
                "confidence": confidence,
            },
            "nodes": nodes,
            "edges": edges,
            "groups": list(source_payload.get("groups") or []),
            "warnings": warnings,
            "adapter_hints": {"preferred_layout": "left_to_right", "supports_timeline_comparison": False},
        }
    ).model_dump()
