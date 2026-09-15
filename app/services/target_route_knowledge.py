from __future__ import annotations

import ipaddress
from typing import Any, Optional

from app.db.connection import get_connection
from app.services.bgp_operational_queries import lookup_bgp_by_ip


def _is_private_destination(ip_value: str | None) -> bool:
    if not ip_value:
        return False
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local)


def _normalize_ip(ip_value: str | None) -> str | None:
    if not ip_value:
        return None
    text = str(ip_value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _safe_text(value: Any) -> str:
    return str(value).strip()


def _fetch_existing_measurements(resolved_ip: str) -> tuple[list[int], list[str]]:
    measurement_ids: list[int] = []
    routegraph_runs: list[str] = []
    queries = [
        (
            "select id from active_traceroute_measurements where target = %s::inet order by measured_at desc, id desc;",
            (resolved_ip,),
            "measurement",
        ),
        (
            "select distinct measurement_id from active_traceroute_hops where target = %s::inet order by measurement_id desc;",
            (resolved_ip,),
            "measurement",
        ),
        (
            "select run_uid from external_route_traceroute_runs where target_resolved_ip = %s::inet order by observed_at desc nulls last, run_uid desc;",
            (resolved_ip,),
            "run",
        ),
        (
            """
            select distinct o.source_ref
            from external_route_observations o
            join external_route_hops h on h.id = o.hop_id
            where h.hop_ip = %s::inet or o.target_host = %s
            order by o.source_ref desc;
            """,
            (resolved_ip, resolved_ip),
            "run",
        ),
        (
            "select distinct service_uid from external_route_hop_edges where to_hop_ip = %s::inet or from_hop_ip = %s::inet order by service_uid desc;",
            (resolved_ip, resolved_ip),
            "run",
        ),
        (
            "select distinct service_uid from external_route_service_hop_summary where hop_id in (select id from external_route_hops where hop_ip = %s::inet) order by service_uid desc;",
            (resolved_ip,),
            "run",
        ),
    ]
    with get_connection() as conn:
        with conn.cursor() as cur:
            for sql, params, kind in queries:
                cur.execute(sql, params)
                rows = cur.fetchall()
                for row in rows:
                    value = row[0]
                    if kind == "measurement" and value is not None:
                        measurement_ids.append(int(value))
                    elif kind == "run" and value:
                        text = _safe_text(value)
                        if text and text not in routegraph_runs:
                            routegraph_runs.append(text)
    return sorted(set(measurement_ids), reverse=True), routegraph_runs


def build_target_route_knowledge_report(target: str, resolved_ip: Optional[str] = None) -> dict[str, Any]:
    resolved_ip_value = _normalize_ip(resolved_ip)
    report: dict[str, Any] = {
        "target": target,
        "resolved_ip": resolved_ip_value,
        "destination_bgp_prefix": None,
        "destination_origin_asn": None,
        "destination_as_path": None,
        "bgp_confidence": "unknown",
        "has_existing_traceroute_measurement": False,
        "existing_measurement_ids": [],
        "existing_routegraph_runs": [],
        "knowledge_status": "unknown_bgp_context",
        "what_routebrain_knows": [],
        "what_routebrain_does_not_know": [],
        "next_recommended_action": "",
    }

    if resolved_ip_value is None:
        report["what_routebrain_does_not_know"].append("resolved_ip was not provided and external DNS is disabled in this read-only report")
        report["next_recommended_action"] = "Provide resolved_ip or a persisted resolution result, then re-run the report"
        return report

    if _is_private_destination(resolved_ip_value):
        report["knowledge_status"] = "private_destination_no_public_bgp"
        report["what_routebrain_knows"].append("Destination is private/loopback/link-local, so no public ASN attribution is applied")
        report["what_routebrain_does_not_know"].append("No public BGP attribution is appropriate for this destination")
        report["next_recommended_action"] = "If needed, compare the private segment against surrounding public borders from existing context"
        return report

    bgp_row = lookup_bgp_by_ip(resolved_ip_value)
    if isinstance(bgp_row, dict):
        matched_prefix = bgp_row.get("matched_prefix")
        origin_asn = bgp_row.get("origin_asn")
        sample_as_paths = bgp_row.get("sample_as_paths")
        as_path = None
        if isinstance(sample_as_paths, list) and sample_as_paths:
            as_path = sample_as_paths[0]
        if matched_prefix and origin_asn is not None:
            report["destination_bgp_prefix"] = str(matched_prefix)
            report["destination_origin_asn"] = int(origin_asn)
            report["destination_as_path"] = str(as_path) if as_path else None
            report["bgp_confidence"] = "high"
            report["what_routebrain_knows"].append(f"Destination IP is covered by BGP prefix {matched_prefix}")
            report["what_routebrain_knows"].append(f"Origin ASN is AS{origin_asn}")
            if as_path:
                report["what_routebrain_knows"].append(f"Observed AS path context includes {as_path}")
            report["knowledge_status"] = "bgp_known_traceroute_missing"
    if report["destination_bgp_prefix"] is None:
        report["what_routebrain_does_not_know"].append("No matching BGP prefix was found for the resolved IP")
        report["next_recommended_action"] = "Resolve the target against persisted context, or run a BGP lookup after data is available"
    else:
        measurement_ids, routegraph_runs = _fetch_existing_measurements(resolved_ip_value)
        report["existing_measurement_ids"] = measurement_ids
        report["existing_routegraph_runs"] = routegraph_runs
        report["has_existing_traceroute_measurement"] = bool(measurement_ids or routegraph_runs)
        if report["has_existing_traceroute_measurement"]:
            report["knowledge_status"] = "bgp_known_traceroute_present"
            report["next_recommended_action"] = "Compare the persisted traceroute measurement against the known BGP context"
        else:
            report["what_routebrain_does_not_know"].append(
                "No persisted traceroute measurement from this RouteBrain instance to this target was found"
            )
            report["next_recommended_action"] = "Run and persist an active traceroute measurement, then compare observed hops with BGP context"
    if not report["next_recommended_action"]:
        report["next_recommended_action"] = "Investigate persisted context before measuring"
    return report
