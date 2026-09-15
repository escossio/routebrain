from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any, Optional

from app.db.connection import get_connection
from app.services.bgp_operational_queries import lookup_bgp_by_ip
from psycopg.rows import dict_row


def _normalize_ip(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


_RAW_LINE_IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F:]{2,})|(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4})\b")


def _extract_hop_ip(hop: dict[str, Any]) -> str | None:
    hop_ip = _normalize_ip(hop.get("hop_ip"))
    if hop_ip:
        return hop_ip
    raw_line = hop.get("raw_line")
    if not raw_line:
        return None
    match = _RAW_LINE_IP_RE.search(str(raw_line))
    if not match:
        return None
    return _normalize_ip(match.group(1))


def _ip_kind(ip_value: str | None) -> str:
    if not ip_value:
        return "unknown_gap"
    address = ipaddress.ip_address(ip_value)
    if address.is_loopback or address.is_link_local or address.is_private:
        return "operator_private_core"
    return "public_backbone"


def _public_hop_context(ip_value: str | None) -> dict[str, Any]:
    if not ip_value:
        return {}
    bgp_row = lookup_bgp_by_ip(ip_value)
    return bgp_row if isinstance(bgp_row, dict) else {}


def _is_cgnat_ip(ip_value: str | None) -> bool:
    if not ip_value:
        return False
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return address in ipaddress.ip_network("100.64.0.0/10")


def _normalize_hop_fact(
    hop: dict[str, Any],
    *,
    hop_index: int,
    destination_ip: str | None,
    source_measurement_id: int,
) -> dict[str, Any]:
    hop_ip = _extract_hop_ip(hop)
    responded = bool(hop.get("responded"))
    is_silent = not responded or hop_ip is None
    is_private = bool(hop_ip and ipaddress.ip_address(hop_ip).is_private)
    is_public = bool(hop_ip and not is_private and not _is_cgnat_ip(hop_ip))
    is_destination = bool(destination_ip and hop_ip == destination_ip)
    hop_type = "silent" if is_silent else "destination" if is_destination else "private" if is_private else "public" if is_public else "unknown"
    bgp_row = _public_hop_context(hop_ip) if is_public else {}
    evidence = {
        "source_table": "active_traceroute_hops",
        "measurement_id": source_measurement_id,
        "hop_number": hop.get("hop_number") or hop_index,
        "responded": responded,
        "raw_line": hop.get("raw_line"),
    }
    if bgp_row:
        evidence["bgp_lookup"] = {
            "matched_prefix": bgp_row.get("matched_prefix"),
            "origin_asn": bgp_row.get("origin_asn"),
            "sample_as_paths": bgp_row.get("sample_as_paths"),
        }
    return {
        "hop_index": hop.get("hop_number") or hop_index,
        "ip": hop_ip,
        "raw_host": None,
        "hop_type": hop_type,
        "is_silent": is_silent,
        "is_private": is_private,
        "is_public": is_public,
        "is_destination": is_destination,
        "loss_percent": None,
        "avg_ms": hop.get("rtt_avg_ms"),
        "reverse_dns": None,
        "rdns_domain": None,
        "bgp_prefix": bgp_row.get("matched_prefix") if bgp_row else None,
        "origin_asn": int(bgp_row["origin_asn"]) if bgp_row.get("origin_asn") is not None and is_public else None,
        "as_path": (bgp_row.get("sample_as_paths") or [None])[0] if bgp_row else None,
        "confidence": "high" if is_destination or is_public else "medium" if is_private else "low",
        "evidence": evidence,
    }


def _segment_key_for_hop(hop: dict[str, Any], *, is_first: bool, is_last: bool) -> tuple[str, str | int | None]:
    if not hop.get("responded"):
        return "silent_gap", None
    hop_ip = _extract_hop_ip(hop)
    if is_first and hop_ip is not None:
        return "local_lan", None
    if is_last and hop_ip is not None:
        return "destination_edge", None
    if hop_ip is None:
        return "unknown_gap", None
    address = ipaddress.ip_address(hop_ip)
    if address.is_private or address.is_loopback or address.is_link_local:
        return "operator_private_core", "private"
    public_context = _public_hop_context(hop_ip)
    public_asn = public_context.get("origin_asn")
    if public_asn is not None:
        return "public_backbone", int(public_asn)
    return "public_operator_edge", "public"


def _segment_type_for_public_last_hop(previous_segment_type: str | None) -> str:
    if previous_segment_type == "operator_private_core":
        return "on_net_destination_edge"
    return "destination_edge"


def _fingerprint(segments: list[dict[str, Any]]) -> tuple[str, str]:
    exact_parts = [f"{segment['segment_type']}:{','.join(segment.get('hops') or []) or '*'}" for segment in segments]
    structural_parts = [f"{segment['segment_type']}:{segment.get('context_label') or segment.get('structural_fingerprint')}" for segment in segments]
    return " | ".join(exact_parts), " -> ".join(structural_parts)


def _fetch_latest_observation(target: str, resolved_ip: str | None, measurement_id: int | None = None) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            if measurement_id is not None:
                cur.execute(
                    """
                    select
                      id,
                      target::text as target,
                      target_label,
                      source_label,
                      mode,
                      status,
                      measured_at,
                      command
                    from active_traceroute_measurements
                    where id = %s
                    limit 1;
                    """,
                    (measurement_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
            if resolved_ip:
                cur.execute(
                    """
                    select
                      id,
                      target::text as target,
                      target_label,
                      source_label,
                      mode,
                      status,
                      measured_at,
                      command
                    from active_traceroute_measurements
                    where target = %s::inet
                    order by measured_at desc, id desc
                    limit 1;
                    """,
                    (resolved_ip,),
                )
            else:
                cur.execute(
                    """
                    select
                      id,
                      target::text as target,
                      target_label,
                      source_label,
                      mode,
                      status,
                      measured_at,
                      command
                    from active_traceroute_measurements
                    where target_label = %s or target::text = %s
                    order by measured_at desc, id desc
                    limit 1;
                    """,
                    (target, target),
                )
            row = cur.fetchone()
    return dict(row) if row else None


def _fetch_observation_hops(measurement_id: int) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                  hop_number,
                  hop_ip::text as hop_ip,
                  responded,
                  rtt_avg_ms,
                  raw_line
                from active_traceroute_hops
                where measurement_id = %s
                order by hop_number, id;
                """,
                (measurement_id,),
            )
            return [dict(row) for row in cur.fetchall()]


def _fetch_related_routegraph_runs(resolved_ip: str | None, measurement_id: int | None) -> list[str]:
    runs: list[str] = []
    with get_connection() as conn:
        with conn.cursor() as cur:
            if measurement_id is not None:
                cur.execute(
                    """
                    select distinct traceroute_run_ref::text
                    from external_route_hop_edges
                    where traceroute_run_ref is not null
                      and (traceroute_run_ref::text = %s or service_uid = %s or target_uid = %s)
                    order by traceroute_run_ref::text desc;
                    """,
                    (str(measurement_id), str(measurement_id), str(measurement_id)),
                )
                runs.extend(row[0] for row in cur.fetchall() if row and row[0])
            if resolved_ip is not None:
                cur.execute(
                    """
                    select distinct run_uid::text
                    from external_route_traceroute_runs
                    where target_resolved_ip = %s::inet
                    order by run_uid::text desc;
                    """,
                    (resolved_ip,),
                )
                runs.extend(row[0] for row in cur.fetchall() if row and row[0])
    return list(dict.fromkeys(runs))


def _segmentize_hops(hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    if not hops:
        return segments
    current: dict[str, Any] | None = None

    def _close_segment(segment: dict[str, Any] | None) -> None:
        if not segment:
            return
        segment["hop_count"] = int(segment["end_hop"]) - int(segment["start_hop"]) + 1
        segment["exact_fingerprint"], segment["structural_fingerprint"] = _fingerprint([segment])
        segment["human_summary"] = segment["segment_type"].replace("_", " ")
        segments.append(segment)

    for index, hop in enumerate(hops, start=1):
        segment_type, segment_key = _segment_key_for_hop(hop, is_first=index == 1, is_last=index == len(hops))
        if index == len(hops) and segment_type == "destination_edge":
            segment_type = _segment_type_for_public_last_hop(current["segment_type"] if current else None)
        ip_value = _extract_hop_ip(hop)
        if current and current["segment_type"] == segment_type and current.get("segment_key") == segment_key:
            current["end_hop"] = index
            if ip_value:
                current["hops"].append(ip_value)
            current["contains_private"] = current["contains_private"] or bool(ip_value and ipaddress.ip_address(ip_value).is_private)
            current["contains_public"] = current["contains_public"] or bool(ip_value and not ipaddress.ip_address(ip_value).is_private)
            current["contains_silent"] = current["contains_silent"] or not bool(hop.get("responded"))
            current["confidence"] = "high" if hop.get("responded") else current["confidence"]
            continue
        _close_segment(current)
        current = {
            "observed_segment_id": f"seg-{len(segments) + 1}",
            "segment_type": segment_type,
            "segment_key": segment_key,
            "start_hop": index,
            "end_hop": index,
            "hop_count": 1,
            "hops": [ip_value] if ip_value else [],
            "contains_private": bool(ip_value and ipaddress.ip_address(ip_value).is_private),
            "contains_cgnat": False,
            "contains_public": bool(ip_value and not ipaddress.ip_address(ip_value).is_private),
            "contains_silent": not bool(hop.get("responded")),
            "contains_mpls": False,
            "first_public_asn": segment_key if segment_type == "public_backbone" else None,
            "last_public_asn": segment_key if segment_type == "public_backbone" else None,
            "previous_public_asn": None,
            "next_public_asn": None,
            "context_asn": segment_key if segment_type == "public_backbone" else None,
            "asn_sequence": [segment_key] if segment_type == "public_backbone" and segment_key is not None else [],
            "rdns_signature": None,
            "exact_fingerprint": "",
            "structural_fingerprint": "",
            "confidence": "high" if hop.get("responded") else "low",
            "human_summary": "",
            "context_label": f"AS{segment_key}" if segment_type == "public_backbone" and segment_key is not None else segment_type,
        }
    _close_segment(current)
    return segments


def _match_segments(segments: list[dict[str, Any]], bgp_row: dict[str, Any] | None) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for segment in segments:
        match_type = "segment_match"
        if segment["segment_type"] in {"destination_edge", "on_net_destination_edge"} and bgp_row and bgp_row.get("origin_asn") is not None:
            match_type = "destination_asn_match"
        elif segment["segment_type"] == "silent_gap":
            match_type = "partial_match"
        elif segment["segment_type"] == "public_backbone":
            match_type = "structural_prefix_match"
        divergence_type: str | None = None
        if segment["segment_type"] == "operator_private_core":
            divergence_type = "private_branch_variation"
        elif segment["segment_type"] in {"destination_edge", "on_net_destination_edge"}:
            divergence_type = "operational_divergence" if match_type != "destination_asn_match" else "structural_divergence"
        elif segment["segment_type"] == "public_backbone":
            divergence_type = "structural_divergence"
        elif segment["segment_type"] == "silent_gap":
            divergence_type = "exact_divergence"
        matches.append(
            {
                "match_id": f"match-{segment['observed_segment_id']}",
                "observed_segment_id": segment["observed_segment_id"],
                "known_segment_id": f"known-{segment['segment_type']}",
                "match_type": match_type,
                "match_score": 90 if match_type == "destination_asn_match" else 80 if match_type == "structural_prefix_match" else 70 if segment["segment_type"] != "unknown_gap" else 25,
                "matched_hops_count": segment["hop_count"],
                "start_hop": segment["start_hop"],
                "end_hop": segment["end_hop"],
                "divergence_hop": None,
                "divergence_type": divergence_type,
                "confidence": segment["confidence"],
                "decision": "reuse" if match_type != "partial_match" else "observe",
                "evidence": [segment["segment_type"]],
                "explanation": (
                    "Private hops do not receive public ASN attribution directly. "
                    if segment["segment_type"] == "operator_private_core"
                    else ""
                )
                + f"Segmento {segment['segment_type']} comparado por leitura read-only.",
            }
        )
    return matches


def build_route_memory_report(target: str, resolved_ip: Optional[str] = None, measurement_id: int | None = None) -> dict[str, Any]:
    resolved_ip_value = _normalize_ip(resolved_ip)
    observation = _fetch_latest_observation(target, resolved_ip_value, measurement_id=measurement_id)
    report: dict[str, Any] = {
        "target": target,
        "resolved_ip": resolved_ip_value,
        "source_node": None,
        "observation_id": None,
        "observed_at": None,
        "tool": None,
        "status": "unknown",
        "destination_bgp_prefix": None,
        "destination_origin_asn": None,
        "destination_as_path": None,
        "bgp_confidence": "unknown",
        "has_existing_traceroute_measurement": False,
        "existing_measurement_ids": [],
        "existing_routegraph_runs": [],
        "knowledge_status": "unknown",
        "observed_segments": [],
        "known_segments": [],
        "segment_matches": [],
        "route_memory_events": [],
        "route_known_fraction": 0.0,
        "common_prefix_known_hops": 0,
        "divergence_hop": None,
        "destination_matches_bgp": False,
        "what_routebrain_knows": [],
        "what_routebrain_does_not_know": [],
        "next_recommended_action": "",
    }
    if observation:
        report["observation_id"] = observation["id"]
        report["source_node"] = observation.get("source_label")
        report["observed_at"] = str(observation.get("measured_at"))
        report["tool"] = observation.get("mode")
        hops = _fetch_observation_hops(int(observation["id"]))
        report["hops"] = [
            _normalize_hop_fact(
                hop,
                hop_index=index,
                destination_ip=resolved_ip_value,
                source_measurement_id=int(observation["id"]),
            )
            for index, hop in enumerate(hops, start=1)
        ]
        report["existing_measurement_ids"] = [int(observation["id"])]
        report["has_existing_traceroute_measurement"] = True
        bgp_row = lookup_bgp_by_ip(resolved_ip_value) if resolved_ip_value else None
        if isinstance(bgp_row, dict) and bgp_row.get("matched_prefix") and bgp_row.get("origin_asn") is not None:
            report["destination_bgp_prefix"] = str(bgp_row["matched_prefix"])
            report["destination_origin_asn"] = int(bgp_row["origin_asn"])
            sample_as_paths = bgp_row.get("sample_as_paths") or []
            report["destination_as_path"] = str(sample_as_paths[0]) if sample_as_paths else None
            report["bgp_confidence"] = "high"
            report["destination_matches_bgp"] = True
        segments = _segmentize_hops(hops)
        matches = _match_segments(segments, bgp_row if isinstance(bgp_row, dict) else None)
        report["observed_segments"] = segments
        report["segment_matches"] = matches
        total_hops = sum(int(segment.get("hop_count") or 0) for segment in segments) or 1
        known_hops = sum(int(segment.get("hop_count") or 0) for segment, match in zip(segments, matches) if match["match_score"] >= 70)
        report["route_known_fraction"] = round(known_hops / total_hops, 3)
        report["common_prefix_known_hops"] = next((item["start_hop"] - 1 for item in matches if item["match_score"] < 70), total_hops)
        report["divergence_hop"] = next((item["start_hop"] for item in matches if item["match_score"] < 70), None)
        report["known_segments"] = [
            {
                "known_segment_id": f"known-{segment['segment_type']}",
                "segment_type": segment["segment_type"],
                "canonical_name": segment["segment_type"],
                "structural_fingerprint": segment["structural_fingerprint"],
                "exact_fingerprint_examples": [segment["exact_fingerprint"]],
                "context_asn": report["destination_origin_asn"] if segment["segment_type"] == "destination_edge" else None,
                "asn_sequence": [report["destination_origin_asn"]] if segment["segment_type"] == "destination_edge" and report["destination_origin_asn"] else [],
                "first_public_asn": report["destination_origin_asn"],
                "last_public_asn": report["destination_origin_asn"],
                "rdns_signature": None,
                "contains_private": segment["contains_private"],
                "contains_cgnat": segment["contains_cgnat"],
                "contains_mpls": segment["contains_mpls"],
                "observed_count": 1,
                "first_seen_at": report["observed_at"],
                "last_seen_at": report["observed_at"],
                "state": "observed" if segment["segment_type"] in {"silent_gap", "unknown_gap"} else "candidate",
                "confidence": segment["confidence"],
                "example_observation_ids": [report["observation_id"]],
                "human_explanation": f"Segmento {segment['segment_type']} reaproveitável em comparação read-only.",
                "evidence": [segment["segment_type"]],
                "ignorance_notes": [],
            }
            for segment in segments
        ]
        report["existing_routegraph_runs"] = _fetch_related_routegraph_runs(resolved_ip_value, int(observation["id"]))
        report["route_memory_events"] = [
            {
                "event_id": f"evt-{observation['id']}-{segment['observed_segment_id']}",
                "event_type": "segment_observed",
                "source_node": report["source_node"],
                "known_segment_id": f"known-{segment['segment_type']}",
                "observation_id": observation["id"],
                "severity": "low" if segment["segment_type"] in {"silent_gap", "unknown_gap"} else "medium",
                "old_value": None,
                "new_value": segment["structural_fingerprint"],
                "created_at": report["observed_at"],
                "explanation": f"Segmento {segment['segment_type']} observado nesta rota.",
            }
            for segment in segments
        ]
        report["knowledge_status"] = "learned" if report["route_known_fraction"] >= 0.7 else "candidate"
        report["what_routebrain_knows"].append("Existe pelo menos uma medição persistida para este destino")
        if report["destination_matches_bgp"]:
            report["what_routebrain_knows"].append("O destino final bate com o contexto BGP conhecido")
        report["what_routebrain_does_not_know"].append(
            "Private hops do not receive public ASN attribution directly; the private segment is contextualized by the following public destination or edge."
        )
        report["what_routebrain_does_not_know"].append("A segmentação ainda é heurística e pode ser refinada com mais histórico")
        report["next_recommended_action"] = "Compare a rota observada com histórico adicional e promova segmentos recorrentes com validação"
        return report

    report["knowledge_status"] = "unknown"
    report["hops"] = []
    report["what_routebrain_does_not_know"].append("Não encontrei medição persistida para este alvo")
    if resolved_ip_value:
        bgp_row = lookup_bgp_by_ip(resolved_ip_value)
        if isinstance(bgp_row, dict) and bgp_row.get("matched_prefix") and bgp_row.get("origin_asn") is not None:
            report["destination_bgp_prefix"] = str(bgp_row["matched_prefix"])
            report["destination_origin_asn"] = int(bgp_row["origin_asn"])
            sample_as_paths = bgp_row.get("sample_as_paths") or []
            report["destination_as_path"] = str(sample_as_paths[0]) if sample_as_paths else None
            report["bgp_confidence"] = "high"
            report["knowledge_status"] = "candidate"
            report["what_routebrain_knows"].append(f"O destino IP está coberto por {report['destination_bgp_prefix']}")
            report["what_routebrain_knows"].append(f"O origin ASN é AS{report['destination_origin_asn']}")
            report["next_recommended_action"] = "Execute uma medição persistida e compare os segmentos observados com este contexto BGP"
        else:
            report["what_routebrain_does_not_know"].append("Não há contexto BGP conhecido para o IP resolvido")
            report["next_recommended_action"] = "Resolver o destino em contexto persistido ou enriquecer o BGP antes de medir"
    else:
        report["next_recommended_action"] = "Forneça resolved_ip ou uma medição persistida para segmentação"
    return report


def compare_route_memory_reports(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_segments = left.get("observed_segments") if isinstance(left.get("observed_segments"), list) else []
    right_segments = right.get("observed_segments") if isinstance(right.get("observed_segments"), list) else []
    paired = list(zip(left_segments, right_segments))
    segment_comparisons: list[dict[str, Any]] = []
    for left_segment, right_segment in paired:
        left_type = str(left_segment.get("segment_type") or "unknown")
        right_type = str(right_segment.get("segment_type") or "unknown")
        divergence_type: str | None = None
        match_type = "partial_match"
        if left_type == right_type:
            match_type = "segment_match"
            if left_type == "operator_private_core":
                left_hops = [hop for hop in left_segment.get("hops") or [] if hop]
                right_hops = [hop for hop in right_segment.get("hops") or [] if hop]
                divergence_type = "private_branch_variation" if left_hops != right_hops else "structural_divergence"
            elif left_type in {"destination_edge", "on_net_destination_edge"}:
                left_asn = left.get("destination_origin_asn")
                right_asn = right.get("destination_origin_asn")
                if left_asn is not None and right_asn is not None and int(left_asn) == int(right_asn):
                    match_type = "destination_asn_match"
                    divergence_type = "structural_divergence"
                else:
                    divergence_type = "operational_divergence"
            elif left_type == "public_backbone":
                divergence_type = "structural_divergence"
            elif left_type == "silent_gap":
                divergence_type = "exact_divergence"
            else:
                divergence_type = "exact_divergence"
        else:
            divergence_type = "operational_divergence"
        segment_comparisons.append(
            {
                "left_segment_type": left_type,
                "right_segment_type": right_type,
                "match_type": match_type,
                "divergence_type": divergence_type,
                "left_hop_count": left_segment.get("hop_count"),
                "right_hop_count": right_segment.get("hop_count"),
            }
        )
    private_branch_variation = any(item["divergence_type"] == "private_branch_variation" for item in segment_comparisons)
    operational_divergence = any(item["divergence_type"] == "operational_divergence" for item in segment_comparisons)
    destination_asn_match = any(item["match_type"] == "destination_asn_match" for item in segment_comparisons)
    return {
        "segment_comparisons": segment_comparisons,
        "private_branch_variation": private_branch_variation,
        "operational_divergence": operational_divergence,
        "destination_asn_match": destination_asn_match,
    }
