from __future__ import annotations

from typing import Any

TOPOLOGY_VIEW_CONTRACT = "routebrain_topology_view.v0_1"
TOPOLOGY_VIEW_VERSION = "0.1"

TOPOLOGY_NODE_TYPES = {
    "origin",
    "local_gateway",
    "private_core",
    "private_hop",
    "public_hop",
    "possible_edge",
    "confirmed_edge",
    "transit_asn",
    "destination_asn",
    "destination_prefix",
    "destination_target",
    "silent_gap",
    "unknown_gap",
    "shared_segment",
    "divergence_point",
    "measurement_group",
    "bgp_context",
    "internet_cloud",
}

NODE_TYPES = TOPOLOGY_NODE_TYPES

TOPOLOGY_LINK_TYPES = {
    "observed_link",
    "shared_link",
    "private_link",
    "public_link",
    "inferred_link",
    "silent_link",
    "divergent_link",
    "bgp_expected_path",
    "unverified_path",
    "destination_reached_link",
}

LINK_TYPES = TOPOLOGY_LINK_TYPES

TOPOLOGY_CONFIDENCE_LEVELS = {
    "observed",
    "inferred",
    "bgp_expected",
    "partial",
    "unknown",
    "not_attributable",
}

CONFIDENCE_LEVELS = TOPOLOGY_CONFIDENCE_LEVELS

_ROOT_REQUIRED_KEYS = {
    "contract",
    "version",
    "topology_uid",
    "graph_uid",
    "measurement_context",
    "source_node",
    "source_network_context",
    "probe_method",
    "created_at",
    "scope_statement",
    "nodes",
    "links",
    "groups",
    "legend",
    "warnings",
    "limitations",
    "evidence_summary",
}


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def validate_topology_view_contract(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["payload must be a dict"]

    if payload.get("contract") != TOPOLOGY_VIEW_CONTRACT:
        errors.append(f"contract must be {TOPOLOGY_VIEW_CONTRACT}")
    if payload.get("version") != TOPOLOGY_VIEW_VERSION:
        errors.append(f"version must be {TOPOLOGY_VIEW_VERSION}")

    for key in sorted(_ROOT_REQUIRED_KEYS):
        if key not in payload:
            errors.append(f"missing required root key: {key}")

    topology_uid = payload.get("topology_uid")
    graph_uid = payload.get("graph_uid")
    measurement_context = payload.get("measurement_context")
    source_node = payload.get("source_node")
    probe_method = payload.get("probe_method")
    scope_statement = payload.get("scope_statement")

    if not _is_non_empty_string(topology_uid):
        errors.append("topology_uid must be a non-empty string")
    if not _is_non_empty_string(graph_uid):
        errors.append("graph_uid must be a non-empty string")
    if not _is_non_empty_string(measurement_context):
        errors.append("measurement_context must be a non-empty string")
    if not _is_non_empty_string(source_node):
        errors.append("source_node must be a non-empty string")
    if not _is_non_empty_string(probe_method):
        errors.append("probe_method must be a non-empty string")
    if not _is_non_empty_string(scope_statement):
        errors.append("scope_statement must be a non-empty string")

    nodes = payload.get("nodes")
    links = payload.get("links")
    groups = payload.get("groups")
    legend = payload.get("legend")
    warnings = payload.get("warnings")
    limitations = payload.get("limitations")
    evidence_summary = payload.get("evidence_summary")

    if not isinstance(nodes, list):
        errors.append("nodes must be a list")
        nodes = []
    if not isinstance(links, list):
        errors.append("links must be a list")
        links = []
    if not isinstance(groups, list):
        errors.append("groups must be a list")
        groups = []
    if not isinstance(warnings, list):
        errors.append("warnings must be a list")
    if not isinstance(limitations, list):
        errors.append("limitations must be a list")
    if not isinstance(legend, dict):
        errors.append("legend must be a dict")
        legend = {}
    if not isinstance(evidence_summary, dict):
        errors.append("evidence_summary must be a dict")

    node_ids: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"nodes[{index}] must be a dict")
            continue
        node_id = node.get("id")
        node_type = node.get("type")
        node_label = node.get("label")
        node_confidence = node.get("confidence")
        if not _is_non_empty_string(node_id):
            errors.append(f"nodes[{index}].id must be a non-empty string")
        else:
            node_ids.add(node_id)
        if node_type not in TOPOLOGY_NODE_TYPES:
            errors.append(f"nodes[{index}].type must be a valid topology node type")
        if not _is_non_empty_string(node_label):
            errors.append(f"nodes[{index}].label must be a non-empty string")
        if node_confidence not in TOPOLOGY_CONFIDENCE_LEVELS:
            errors.append(f"nodes[{index}].confidence must be a valid confidence level")
        evidence = node.get("evidence")
        style_hint = node.get("style_hint")
        if not isinstance(evidence, list):
            errors.append(f"nodes[{index}].evidence must be a list")
        if not isinstance(style_hint, dict):
            errors.append(f"nodes[{index}].style_hint must be a dict")
        asn = node.get("asn")
        if not (asn is None or isinstance(asn, int)):
            errors.append(f"nodes[{index}].asn must be null or integer")
        for field in ("subtitle", "role", "ip", "as_name", "prefix", "group_id"):
            value = node.get(field)
            if not (value is None or isinstance(value, str)):
                errors.append(f"nodes[{index}].{field} must be null or string")

    for index, link in enumerate(links):
        if not isinstance(link, dict):
            errors.append(f"links[{index}] must be a dict")
            continue
        link_id = link.get("id")
        link_source = link.get("source")
        link_target = link.get("target")
        link_type = link.get("type")
        link_confidence = link.get("confidence")
        observed = link.get("observed")
        inferred = link.get("inferred")
        if not _is_non_empty_string(link_id):
            errors.append(f"links[{index}].id must be a non-empty string")
        if not _is_non_empty_string(link_source):
            errors.append(f"links[{index}].source must be a non-empty string")
        elif link_source not in node_ids:
            errors.append(f"links[{index}].source must reference an existing node id")
        if not _is_non_empty_string(link_target):
            errors.append(f"links[{index}].target must be a non-empty string")
        elif link_target not in node_ids:
            errors.append(f"links[{index}].target must reference an existing node id")
        if link_type not in TOPOLOGY_LINK_TYPES:
            errors.append(f"links[{index}].type must be a valid topology link type")
        if link_confidence not in TOPOLOGY_CONFIDENCE_LEVELS:
            errors.append(f"links[{index}].confidence must be a valid confidence level")
        if not isinstance(observed, bool):
            errors.append(f"links[{index}].observed must be a boolean")
        if not isinstance(inferred, bool):
            errors.append(f"links[{index}].inferred must be a boolean")
        routes_count = link.get("routes_count")
        if routes_count is not None and (not isinstance(routes_count, int) or routes_count < 0):
            errors.append(f"links[{index}].routes_count must be an integer >= 0")
        evidence = link.get("evidence")
        style_hint = link.get("style_hint")
        if not isinstance(evidence, list):
            errors.append(f"links[{index}].evidence must be a list")
        if not isinstance(style_hint, dict):
            errors.append(f"links[{index}].style_hint must be a dict")

    for index, group in enumerate(groups):
        if not isinstance(group, dict):
            errors.append(f"groups[{index}] must be a dict")
            continue
        group_id = group.get("id")
        group_type = group.get("type")
        group_label = group.get("label")
        group_nodes = group.get("nodes")
        if not _is_non_empty_string(group_id):
            errors.append(f"groups[{index}].id must be a non-empty string")
        if not _is_non_empty_string(group_type):
            errors.append(f"groups[{index}].type must be a non-empty string")
        if not _is_non_empty_string(group_label):
            errors.append(f"groups[{index}].label must be a non-empty string")
        if not isinstance(group_nodes, list):
            errors.append(f"groups[{index}].nodes must be a list")
            continue
        for node_id in group_nodes:
            if not isinstance(node_id, str) or node_id not in node_ids:
                errors.append(f"groups[{index}].nodes must reference existing node ids")
                break
        summary = group.get("summary")
        if not (summary is None or isinstance(summary, str)):
            errors.append(f"groups[{index}].summary must be null or string")

    legend_obj = _as_dict(legend)
    for field in ("title", "scope_notice", "color_rules", "line_rules", "confidence_rules"):
        if field not in legend_obj:
            errors.append(f"legend missing required key: {field}")
    if not _is_non_empty_string(legend_obj.get("title")):
        errors.append("legend.title must be a non-empty string")
    if not _is_non_empty_string(legend_obj.get("scope_notice")):
        errors.append("legend.scope_notice must be a non-empty string")
    if not isinstance(legend_obj.get("color_rules"), dict):
        errors.append("legend.color_rules must be a dict")
    if not isinstance(legend_obj.get("line_rules"), dict):
        errors.append("legend.line_rules must be a dict")
    if not isinstance(legend_obj.get("confidence_rules"), dict):
        errors.append("legend.confidence_rules must be a dict")

    return errors
