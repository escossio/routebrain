from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

from app.services.route_memory_persistence import resolve_best_hop_facts

def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join("" if part is None else str(part) for part in parts)
    digest = hashlib.sha1(material.encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:20]}"


def _confidence_rank(value: str | None) -> int:
    ordering = {"high": 3, "medium": 2, "low": 1, "unknown": 0}
    return ordering.get(str(value or "unknown").lower(), 0)


def _normalize_label(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = " ".join(text.split())
    return text


def _first_non_empty(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _segment_fingerprint_for_hop(hop: dict[str, Any]) -> str | None:
    if hop.get("segment_fingerprint"):
        return str(hop.get("segment_fingerprint"))
    if hop.get("structural_fingerprint"):
        return str(hop.get("structural_fingerprint"))
    segment_type = _normalize_label(hop.get("hop_type") or hop.get("segment_type"))
    asn = hop.get("origin_asn")
    if segment_type and asn is not None:
        return f"{segment_type}:{asn}"
    return None


def _canonical_hop_key(
    hop: dict[str, Any],
    *,
    observation_uid: str,
    route_id: str,
    hop_index: int | None,
) -> str:
    ip_value = _first_non_empty(hop.get("ip"))
    if ip_value:
        return f"ip:{ip_value}"
    segment_fingerprint = _segment_fingerprint_for_hop(hop)
    if segment_fingerprint:
        return f"segment:{segment_fingerprint}"
    origin_asn = hop.get("origin_asn")
    hop_type = _normalize_label(hop.get("hop_type") or hop.get("segment_type") or "hop")
    if origin_asn is not None:
        return f"asn:{origin_asn}:{hop_type}"
    label = _normalize_label(_first_non_empty(hop.get("raw_host"), hop.get("reverse_dns"), hop.get("label")))
    if label:
        return f"label:{hop_type}:{label}"
    if hop.get("is_silent") or hop.get("hop_type") == "silent" or hop.get("hop_type") == "unknown":
        return f"unknown:{route_id}:{hop_index if hop_index is not None else observation_uid}"
    return f"unknown:{route_id}:{hop_index if hop_index is not None else observation_uid}"


def _canonical_node_key_from_segment(segment: dict[str, Any]) -> str:
    segment_fingerprint = _first_non_empty(segment.get("structural_fingerprint"), segment.get("exact_fingerprint"))
    if segment_fingerprint:
        return f"segment:{segment_fingerprint}"
    segment_type = _normalize_label(segment.get("segment_type") or "segment")
    context_asn = segment.get("context_asn")
    if context_asn is not None:
        return f"asn:{context_asn}:segment"
    label = _normalize_label(segment.get("human_summary") or segment.get("segment_type") or "segment")
    return f"label:segment:{label}" if label else f"unknown:{segment_type}"


def _canonical_node_key_from_hop(
    hop: dict[str, Any],
    *,
    observation_uid: str,
    route_id: str,
    hop_index: int | None,
) -> str:
    return _canonical_hop_key(hop, observation_uid=observation_uid, route_id=route_id, hop_index=hop_index)


def _project_canonical_nodes(
    raw_nodes: list[dict[str, Any]],
    *,
    source_node: str,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    canonical_nodes: dict[str, dict[str, Any]] = {}
    raw_to_canonical_id: dict[str, str] = {}

    for raw_node in raw_nodes:
        raw_node_id = str(raw_node.get("node_id"))
        raw_route_ids = list(raw_node.get("route_ids") or [])
        if raw_node.get("node_type") == "segment":
            canonical_key = str(raw_node.get("canonical_key") or _canonical_node_key_from_segment(raw_node))
        else:
            canonical_key = str(raw_node.get("canonical_key") or raw_node_id)
        canonical_node = canonical_nodes.get(canonical_key)
        if canonical_node is None:
            canonical_node = {
                "node_id": _stable_id("node", canonical_key),
                "canonical_key": canonical_key,
                "label": raw_node.get("label"),
                "node_type": raw_node.get("node_type"),
                "ip": raw_node.get("ip"),
                "asn": raw_node.get("asn"),
                "segment_type": raw_node.get("segment_type"),
                "route_ids": [],
                "shared": False,
                "confidence": raw_node.get("confidence") or "unknown",
                "metrics": raw_node.get("metrics") or {},
                "evidence": [],
                "source_node_ids": [],
                "source_node": source_node,
            }
            canonical_nodes[canonical_key] = canonical_node
        if raw_node_id not in canonical_node["source_node_ids"]:
            canonical_node["source_node_ids"].append(raw_node_id)
        for route_id in raw_route_ids:
            if route_id not in canonical_node["route_ids"]:
                canonical_node["route_ids"].append(route_id)
        if raw_node.get("confidence") and _confidence_rank(raw_node.get("confidence")) > _confidence_rank(canonical_node.get("confidence")):
            canonical_node["confidence"] = raw_node.get("confidence")
        if raw_node.get("evidence"):
            if isinstance(raw_node["evidence"], list):
                canonical_node["evidence"].extend(raw_node["evidence"])
            else:
                canonical_node["evidence"].append(raw_node["evidence"])
        canonical_node["shared"] = len(canonical_node["route_ids"]) > 1
        raw_to_canonical_id[raw_node_id] = canonical_node["node_id"]

    canonical_nodes_list = list(canonical_nodes.values())
    for node in canonical_nodes_list:
        node["route_ids"] = sorted(dict.fromkeys(node["route_ids"]))
        node["source_node_ids"] = sorted(dict.fromkeys(node["source_node_ids"]))
        if node["evidence"]:
            node["evidence"] = list(node["evidence"])
        if node["shared"] and not node.get("label"):
            node["label"] = node.get("canonical_key")
    return canonical_nodes_list, raw_to_canonical_id


def _merge_edge_record(
    edge_map: dict[tuple[str, str, str], dict[str, Any]],
    *,
    source_key: str,
    target_key: str,
    edge_type: str,
    source: str,
    target: str,
    route_id: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    edge_key = (source_key, target_key, edge_type)
    edge = edge_map.get(edge_key)
    if edge is None:
        edge = {
            "edge_id": _stable_id("edge", source_key, target_key, edge_type),
            "source": source,
            "target": target,
            "source_key": source_key,
            "target_key": target_key,
            "route_ids": [],
            "shared": False,
            "edge_type": edge_type,
            "metrics": {},
            "evidence": [],
        }
        edge_map[edge_key] = edge
    if route_id not in edge["route_ids"]:
        edge["route_ids"].append(route_id)
    if evidence:
        edge["evidence"].append(evidence)
    edge["shared"] = len(edge["route_ids"]) > 1


def _canonicalize_existing_edge_nodes(edges: list[dict[str, Any]], raw_to_canonical_id: dict[str, str]) -> None:
    for edge in edges:
        source = raw_to_canonical_id.get(str(edge.get("source")))
        target = raw_to_canonical_id.get(str(edge.get("target")))
        if source:
            edge["source"] = source
        if target:
            edge["target"] = target


def build_route_memory_graph_payload(
    observations: list[dict[str, Any]],
    *,
    source_node: str,
    title: str | None = None,
) -> dict[str, Any]:
    routes: list[dict[str, Any]] = []
    raw_nodes_by_key: dict[tuple[str, str | None, int | None, str | None], dict[str, Any]] = {}
    edges_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    segments_by_key: dict[tuple[str | None, str | None], dict[str, Any]] = {}
    divergences: list[dict[str, Any]] = []

    for index, report in enumerate(observations, start=1):
        observation_uid = str(report.get("observation_uid") or _stable_id("rmo", source_node, report.get("target"), report.get("resolved_ip"), index))
        route_id = f"route_{index}"
        routes.append(
            {
                "route_id": route_id,
                "target": report.get("target"),
                "resolved_ip": report.get("resolved_ip"),
                "color_hint": route_id,
                "observation_uid": observation_uid,
            }
        )
        for segment in report.get("observed_segments") or []:
            if not isinstance(segment, dict):
                continue
            segment_uid = str(
                segment.get("observed_segment_uid")
                or _stable_id(
                    "segment",
                    observation_uid,
                    segment.get("segment_type"),
                    segment.get("start_hop"),
                    segment.get("end_hop"),
                    segment.get("structural_fingerprint"),
                )
            )
            segment_key = (segment.get("segment_type"), segment.get("structural_fingerprint"))
            segment_entry = segments_by_key.get(segment_key)
            if segment_entry is None:
                segment_entry = {
                    "segment_id": segment_uid,
                    "segment_type": segment.get("segment_type"),
                    "start_hop": segment.get("start_hop"),
                    "end_hop": segment.get("end_hop"),
                    "route_ids": [],
                    "shared": False,
                    "context_asn": segment.get("context_asn"),
                    "structural_fingerprint": segment.get("structural_fingerprint"),
                    "confidence": segment.get("confidence") or "unknown",
                    "summary": segment.get("human_summary") or f"{segment.get('segment_type')} segment",
                }
                segments_by_key[segment_key] = segment_entry
            if route_id not in segment_entry["route_ids"]:
                segment_entry["route_ids"].append(route_id)
            if segment.get("confidence") and _confidence_rank(segment.get("confidence")) > _confidence_rank(segment_entry.get("confidence")):
                segment_entry["confidence"] = segment.get("confidence")
            segment_entry["shared"] = len(segment_entry["route_ids"]) > 1
            node_key = (
                "segment",
                segment.get("segment_type"),
                segment.get("context_asn"),
                segment.get("structural_fingerprint"),
            )
            node = raw_nodes_by_key.get(node_key)
            if node is None:
                node_id = _stable_id("node", *node_key)
                node = {
                    "node_id": node_id,
                    "canonical_key": _canonical_node_key_from_segment(segment),
                    "label": segment.get("context_asn") and f"AS{segment.get('context_asn')}" or str(segment.get("segment_type") or "segment"),
                    "node_type": "segment",
                    "ip": None,
                    "asn": segment.get("context_asn"),
                    "segment_type": segment.get("segment_type"),
                    "route_ids": [],
                    "shared": False,
                    "confidence": segment.get("confidence") or "unknown",
                    "metrics": {},
                    "evidence": segment.get("evidence") or {},
                }
                raw_nodes_by_key[node_key] = node
            if route_id not in node["route_ids"]:
                node["route_ids"].append(route_id)
            if segment.get("confidence") and _confidence_rank(segment.get("confidence")) > _confidence_rank(node.get("confidence")):
                node["confidence"] = segment.get("confidence")
            node["shared"] = len(node["route_ids"]) > 1

        previous_node_id: str | None = None
        previous_hop_key: str | None = None
        hop_source = report.get("hop_facts") if isinstance(report.get("hop_facts"), list) and report.get("hop_facts") else report.get("hops") or []
        for hop in resolve_best_hop_facts([hop for hop in hop_source if isinstance(hop, dict)]):
            # A selected fact is evidence, not proof of globally scoped attribution.
            direct_asn = hop.get("origin_asn")
            if hop.get("ip") is not None:
                try:
                    if not ipaddress.ip_address(str(hop["ip"])).is_global:
                        direct_asn = None
                except ValueError:
                    direct_asn = None
            hop_index = hop.get("hop_index") if hop.get("hop_index") is not None else None
            hop_id = _stable_id("hop", observation_uid, hop.get("hop_index") or hop.get("hop_number"), hop.get("ip"), hop.get("hop_type"))
            hop_key = _canonical_hop_key(hop, observation_uid=observation_uid, route_id=route_id, hop_index=int(hop_index) if hop_index is not None else None)
            node = {
                "node_id": hop_id,
                "canonical_key": _canonical_node_key_from_hop(hop, observation_uid=observation_uid, route_id=route_id, hop_index=int(hop_index) if hop_index is not None else None),
                "label": hop.get("raw_host") or hop.get("reverse_dns") or (f"AS{direct_asn}" if direct_asn else str(hop.get("ip") or "hop")),
                "node_type": "hop",
                "ip": hop.get("ip"),
                "asn": direct_asn,
                "segment_type": hop.get("hop_type"),
                "route_ids": [route_id],
                "shared": False,
                "confidence": hop.get("confidence") or "unknown",
                "metrics": {
                    "loss_percent": hop.get("loss_percent"),
                    "avg_ms": hop.get("avg_ms"),
                },
                "evidence": hop.get("evidence") or {},
            }
            raw_nodes_by_key[("hop", hop_id, None, None)] = node
            if previous_node_id is not None and previous_hop_key is not None:
                _merge_edge_record(
                    edges_by_key,
                    source_key=previous_hop_key,
                    target_key=hop_key,
                    edge_type="route_hop",
                    source=previous_node_id,
                    target=hop_id,
                    route_id=route_id,
                    evidence=hop.get("evidence") or {},
                )
            previous_node_id = hop_id
            previous_hop_key = hop_key

    segments = list(segments_by_key.values())
    nodes, raw_to_canonical_id = _project_canonical_nodes(list(raw_nodes_by_key.values()), source_node=source_node)
    edges = list(edges_by_key.values())
    _canonicalize_existing_edge_nodes(edges, raw_to_canonical_id)
    for collection in (segments, edges, nodes):
        for item in collection:
            if isinstance(item.get("route_ids"), list):
                item["route_ids"] = sorted(dict.fromkeys(item["route_ids"]))
            if isinstance(item.get("evidence"), list):
                item["evidence"] = list(item["evidence"])
    shared_paths = [segment for segment in segments if segment["shared"]]
    for segment in shared_paths:
        route_ids = sorted(segment["route_ids"])
        if len(route_ids) < 2:
            continue
        divergences.append(
            {
                "divergence_id": _stable_id("div", segment["segment_id"], *route_ids),
                "divergence_type": "private_branch_variation" if segment.get("segment_type") == "operator_private_core" else "structural_divergence",
                "at_segment": segment["segment_id"],
                "route_ids": route_ids,
                "summary": "Routes share the same segment shape but differ in route-specific context",
                "severity": "info",
            }
        )

    return {
        "schema": "route_memory_graph.v1",
        "source_node": source_node,
        "title": title or "RouteMemory graph",
        "routes": routes,
        "nodes": nodes,
        "edges": edges,
        "segments": segments,
        "shared_paths": shared_paths,
        "divergences": divergences,
        "legend": [
            {"key": "route", "label": "Route"},
            {"key": "segment", "label": "Segment"},
            {"key": "shared", "label": "Shared"},
            {"key": "divergence", "label": "Divergence"},
        ],
    }
