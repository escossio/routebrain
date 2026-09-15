from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    message: str
    path: str | None = None


@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)


_REQUIRED_TOP_LEVEL_KEYS = ("routes", "nodes", "edges", "segments", "divergences", "legend")
_EVIDENCE_STRONG_PREFIXES = ("ip:", "segment:", "asn:")
_UNKNOWN_MARKERS = ("unknown", "silent")


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _normalized_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _has_strong_evidence_key(value: Any) -> bool:
    text = _normalized_text(value)
    return any(text.startswith(prefix) for prefix in _EVIDENCE_STRONG_PREFIXES)


def _contains_unknown_like(*values: Any) -> bool:
    for value in values:
        text = _normalized_text(value)
        if any(marker in text for marker in _UNKNOWN_MARKERS):
            return True
    return False


def _add_issue(target: list[ValidationIssue], code: str, message: str, path: str | None = None) -> None:
    target.append(ValidationIssue(code=code, message=message, path=path))


def validate_route_memory_graph_payload(payload: dict[str, Any] | Any) -> ValidationResult:
    errors: list[ValidationIssue] = []
    warnings: list[ValidationIssue] = []

    if not isinstance(payload, dict):
        _add_issue(errors, "payload_type", "Payload must be an object/dict.")
        return ValidationResult(is_valid=False, errors=errors, warnings=warnings, summary={"routes_count": 0, "nodes_count": 0, "edges_count": 0, "segments_count": 0, "divergences_count": 0, "shared_nodes_count": 0, "shared_edges_count": 0, "errors_count": 1, "warnings_count": 0})

    missing_keys = [key for key in _REQUIRED_TOP_LEVEL_KEYS if key not in payload]
    for key in missing_keys:
        _add_issue(errors, "missing_top_level", f"Missing required top-level key: {key}.", path=key)

    routes = _as_list(payload.get("routes"))
    nodes = _as_list(payload.get("nodes"))
    edges = _as_list(payload.get("edges"))
    segments = _as_list(payload.get("segments"))
    divergences = _as_list(payload.get("divergences"))
    legend = payload.get("legend")

    for key, value in [
        ("routes", payload.get("routes")),
        ("nodes", payload.get("nodes")),
        ("edges", payload.get("edges")),
        ("segments", payload.get("segments")),
        ("divergences", payload.get("divergences")),
    ]:
        if key in payload and not isinstance(value, list):
            _add_issue(errors, "invalid_type", f"{key} must be a list.", path=key)

    if "legend" in payload and not isinstance(legend, list):
        _add_issue(errors, "invalid_type", "legend must be a list.", path="legend")

    route_ids = []
    for index, route in enumerate(routes):
        if not isinstance(route, dict):
            _add_issue(errors, "route_type", "Route entry must be an object.", path=f"routes[{index}]")
            continue
        route_id = route.get("route_id")
        if not route_id:
            _add_issue(errors, "route_id_missing", "Route is missing route_id.", path=f"routes[{index}].route_id")
            continue
        route_ids.append(str(route_id))

    route_id_set = set(route_ids)
    node_id_set = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            _add_issue(errors, "node_type", "Node entry must be an object.", path=f"nodes[{index}]")
            continue
        node_id = node.get("node_id")
        if not node_id:
            _add_issue(errors, "node_id_missing", "Node is missing node_id.", path=f"nodes[{index}].node_id")
        else:
            node_id_set.add(str(node_id))
        if "route_ids" not in node or not isinstance(node.get("route_ids"), list):
            _add_issue(errors, "node_route_ids_invalid", "Node route_ids must be a list.", path=f"nodes[{index}].route_ids")
        if "shared" not in node:
            _add_issue(errors, "node_shared_missing", "Node is missing shared.", path=f"nodes[{index}].shared")
        if not node.get("canonical_key"):
            _add_issue(warnings, "node_canonical_key_missing", "Node canonical_key is missing.", path=f"nodes[{index}].canonical_key")

    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            _add_issue(errors, "edge_type", "Edge entry must be an object.", path=f"edges[{index}]")
            continue
        edge_id = edge.get("edge_id")
        if not edge_id:
            _add_issue(errors, "edge_id_missing", "Edge is missing edge_id.", path=f"edges[{index}].edge_id")
        if not edge.get("source") or str(edge.get("source")) not in node_id_set:
            _add_issue(errors, "edge_source_invalid", "Edge source must reference an existing node_id.", path=f"edges[{index}].source")
        if not edge.get("target") or str(edge.get("target")) not in node_id_set:
            _add_issue(errors, "edge_target_invalid", "Edge target must reference an existing node_id.", path=f"edges[{index}].target")
        if "route_ids" not in edge or not isinstance(edge.get("route_ids"), list):
            _add_issue(errors, "edge_route_ids_invalid", "Edge route_ids must be a list.", path=f"edges[{index}].route_ids")
        if "shared" not in edge:
            _add_issue(errors, "edge_shared_missing", "Edge is missing shared.", path=f"edges[{index}].shared")
        if not edge.get("source_key"):
            _add_issue(warnings, "edge_source_key_missing", "Edge source_key is missing.", path=f"edges[{index}].source_key")
        if not edge.get("target_key"):
            _add_issue(warnings, "edge_target_key_missing", "Edge target_key is missing.", path=f"edges[{index}].target_key")

    def _check_route_id_membership(items: list[dict[str, Any]], item_name: str) -> None:
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            item_route_ids = item.get("route_ids")
            if not isinstance(item_route_ids, list):
                continue
            normalized_ids = [str(route_id) for route_id in item_route_ids if route_id is not None]
            unknown_ids = [route_id for route_id in normalized_ids if route_id not in route_id_set]
            if unknown_ids:
                _add_issue(errors, "unknown_route_id", f"{item_name} references unknown route_ids: {', '.join(sorted(set(unknown_ids)))}.", path=f"{item_name}[{index}].route_ids")
            shared = bool(item.get("shared"))
            if shared and len(set(normalized_ids)) <= 1:
                _add_issue(errors, "shared_true_single_route", f"{item_name} shared=true requires more than one route_id.", path=f"{item_name}[{index}].shared")
            if not shared and len(set(normalized_ids)) > 1:
                _add_issue(warnings, "shared_false_multiple_routes", f"{item_name} shared=false but references multiple route_ids.", path=f"{item_name}[{index}].shared")

    _check_route_id_membership(nodes, "nodes")
    _check_route_id_membership(edges, "edges")
    _check_route_id_membership(segments, "segments")
    _check_route_id_membership(divergences, "divergences")

    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        if bool(node.get("shared")) and _contains_unknown_like(node.get("node_type"), node.get("segment_type"), node.get("label"), node.get("canonical_key")):
            if not _has_strong_evidence_key(node.get("canonical_key")):
                _add_issue(warnings, "shared_unknown_node", "Shared unknown/silent node should not be treated as fully canonical without strong evidence.", path=f"nodes[{index}]")

    for index, segment in enumerate(segments):
        if not isinstance(segment, dict):
            continue
        if bool(segment.get("shared")) and _contains_unknown_like(segment.get("segment_type"), segment.get("summary"), segment.get("segment_fingerprint")):
            if not _has_strong_evidence_key(segment.get("segment_fingerprint")):
                _add_issue(warnings, "shared_unknown_segment", "Shared unknown/silent segment should not be treated as fully canonical without strong evidence.", path=f"segments[{index}]")

    for index, divergence in enumerate(divergences):
        if not isinstance(divergence, dict):
            _add_issue(errors, "divergence_type", "Divergence entry must be an object.", path=f"divergences[{index}]")
            continue
        if not divergence.get("divergence_id") and not divergence.get("id"):
            _add_issue(errors, "divergence_id_missing", "Divergence is missing an identifier.", path=f"divergences[{index}].divergence_id")
        if not divergence.get("divergence_type"):
            _add_issue(errors, "divergence_type_missing", "Divergence is missing divergence_type.", path=f"divergences[{index}].divergence_type")
        if not isinstance(divergence.get("route_ids"), list) or not divergence.get("route_ids"):
            _add_issue(errors, "divergence_route_ids_missing", "Divergence must reference route_ids.", path=f"divergences[{index}].route_ids")
        else:
            unknown_ids = [str(route_id) for route_id in divergence.get("route_ids") if str(route_id) not in route_id_set]
            if unknown_ids:
                _add_issue(errors, "divergence_route_id_unknown", f"Divergence references unknown route_ids: {', '.join(sorted(set(unknown_ids)))}.", path=f"divergences[{index}].route_ids")
        if not divergence.get("summary"):
            _add_issue(warnings, "divergence_summary_missing", "Divergence summary is missing.", path=f"divergences[{index}].summary")

    routes_count = len(routes)
    nodes_count = len(nodes)
    edges_count = len(edges)
    segments_count = len(segments)
    divergences_count = len(divergences)
    shared_nodes_count = sum(1 for node in nodes if isinstance(node, dict) and bool(node.get("shared")))
    shared_edges_count = sum(1 for edge in edges if isinstance(edge, dict) and bool(edge.get("shared")))

    if routes_count <= 0:
        _add_issue(errors, "routes_empty", "Graph must contain at least one route.", path="routes")
    if nodes_count <= 0:
        _add_issue(errors, "nodes_empty", "Graph must contain at least one node.", path="nodes")
    if edges_count <= 0:
        _add_issue(warnings, "edges_empty", "Graph has no edges.")

    summary = {
        "routes_count": routes_count,
        "nodes_count": nodes_count,
        "edges_count": edges_count,
        "segments_count": segments_count,
        "divergences_count": divergences_count,
        "shared_nodes_count": shared_nodes_count,
        "shared_edges_count": shared_edges_count,
        "errors_count": len(errors),
        "warnings_count": len(warnings),
    }

    return ValidationResult(is_valid=not errors, errors=errors, warnings=warnings, summary=summary)

