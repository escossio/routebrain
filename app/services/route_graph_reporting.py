from __future__ import annotations

from typing import Any

from app.api.route_graph import _source_payload_for_run
from app.services.route_graph_builder import build_route_graph_report, build_route_graph_v1
from app.services.route_graph_validator import validate_route_graph


def build_route_graph_report_for_run(run_uid: str) -> dict[str, Any]:
    source_payload = _source_payload_for_run(run_uid)
    route_graph = build_route_graph_v1(source_payload)
    valid, errors = validate_route_graph(route_graph)
    if not valid:
        raise ValueError("RouteGraph inválido: " + "; ".join(errors))
    return build_route_graph_report(route_graph)


def render_route_graph_report_text(report: dict[str, Any]) -> str:
    lines = [
        f"schema_version: {report.get('schema_version')}",
        f"graph_uid: {report.get('graph_uid')}",
        f"run_uid: {report.get('run_uid')}",
        f"target: {report.get('target')}",
        f"ip_family: {report.get('ip_family')}",
        f"generated_at: {report.get('generated_at')}",
        f"total_nodes: {report.get('total_nodes')}",
        f"total_edges: {report.get('total_edges')}",
        f"logical_hop_count: {report.get('logical_hop_count')}",
        f"responding_hop_count: {report.get('responding_hop_count')}",
        f"silent_hop_count: {report.get('silent_hop_count')}",
        f"private_hop_count: {report.get('private_hop_count')}",
        f"public_hop_count: {report.get('public_hop_count')}",
        f"destination_reached: {report.get('destination_reached')}",
        f"confidence: {report.get('confidence')}",
        f"asn_count: {report.get('asn_count')}",
        f"missing_asn_count: {report.get('missing_asn_count')}",
        f"as_name_count: {report.get('as_name_count')}",
        f"missing_as_name_count: {report.get('missing_as_name_count')}",
        f"latency_count: {report.get('latency_count')}",
        f"missing_latency_count: {report.get('missing_latency_count')}",
        f"evidence_count: {report.get('evidence_count')}",
        f"missing_evidence_count: {report.get('missing_evidence_count')}",
        f"warnings_total: {report.get('warnings_total')}",
        "warnings:",
    ]
    for warning in report.get("warnings") or []:
        lines.append(f"- {warning}")
    lines.append("hops:")
    for hop in report.get("hops") or []:
        lines.append(
            "- "
            + " ".join(
                [
                    f"hop_index={hop.get('hop_index')}",
                    f"id={hop.get('id')}",
                    f"kind={hop.get('kind')}",
                    f"ip={hop.get('ip')}",
                    f"latency_ms={hop.get('latency_ms')}",
                    f"is_private={hop.get('is_private')}",
                    f"is_silent={hop.get('is_silent')}",
                    f"is_destination={hop.get('is_destination')}",
                    f"asn={hop.get('asn')}",
                    f"as_name={hop.get('as_name')}",
                    f"confidence={hop.get('confidence')}",
                    f"evidence_count={hop.get('evidence_count')}",
                    f"badges={hop.get('badges')}",
                ]
            )
        )
    return "\n".join(lines)
