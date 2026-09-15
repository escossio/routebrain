from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any, Iterable

from app.db.connection import get_connection
from psycopg.rows import dict_row


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, Decimal):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def _stable_uid(prefix: str, *parts: Any) -> str:
    material = "|".join("" if part is None else str(part) for part in parts)
    digest = hashlib.sha1(material.encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:24]}"


def _payload_fingerprint(payload: dict[str, Any]) -> str:
    material = json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha1(material.encode("utf-8")).hexdigest()


def _ensure_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _observation_uid(source_node: str, report: dict[str, Any]) -> str:
    return _stable_uid(
        "rmo",
        source_node,
        report.get("target"),
        report.get("resolved_ip"),
        report.get("observation_id"),
        report.get("observed_at"),
        report.get("tool"),
        report.get("knowledge_status"),
    )


def _segment_uid(observation_uid: str, segment: dict[str, Any]) -> str:
    return _stable_uid(
        "rms",
        observation_uid,
        segment.get("segment_type"),
        segment.get("start_hop"),
        segment.get("end_hop"),
        segment.get("exact_fingerprint"),
        segment.get("structural_fingerprint"),
    )


def _match_uid(observation_uid: str, segment_uid: str, match: dict[str, Any]) -> str:
    return _stable_uid(
        "rmm",
        observation_uid,
        segment_uid,
        match.get("match_type"),
        match.get("decision"),
        match.get("divergence_type"),
        match.get("matched_known_segment_id"),
    )


def _event_uid(observation_uid: str, event: dict[str, Any]) -> str:
    return _stable_uid(
        "rme",
        observation_uid,
        event.get("event_id"),
        event.get("event_type"),
        event.get("known_segment_id") or event.get("observed_segment_uid"),
        event.get("explanation"),
        event.get("new_value"),
        event.get("old_value"),
    )


def _route_memory_version(report: dict[str, Any]) -> str:
    return _ensure_text(report.get("route_memory_version"), "v0.7.2")


def _hop_fact_weight(hop_fact: dict[str, Any]) -> tuple[int, int, int, int, int]:
    has_ip = 1 if _ensure_text(hop_fact.get("ip")) else 0
    has_hop_type = 1 if _ensure_text(hop_fact.get("hop_type")) else 0
    public_context = 1 if _ensure_text(hop_fact.get("bgp_prefix")) or hop_fact.get("origin_asn") is not None else 0
    evidence_score = len(hop_fact.get("evidence") or []) if isinstance(hop_fact.get("evidence"), list) else 1 if hop_fact.get("evidence") else 0
    recency = int(hop_fact.get("source_measurement_id") or hop_fact.get("measurement_id") or 0)
    return has_ip, has_hop_type, public_context, evidence_score, recency


def resolve_best_hop_facts(hop_facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
    for hop_fact in hop_facts:
        if not isinstance(hop_fact, dict):
            continue
        key = (hop_fact.get("observation_uid"), hop_fact.get("hop_index"))
        grouped.setdefault(key, []).append(hop_fact)
    resolved: list[dict[str, Any]] = []
    for key in sorted(grouped.keys(), key=lambda item: (str(item[0]), int(item[1]) if item[1] is not None else -1)):
        candidates = grouped[key]
        candidates = sorted(
            candidates,
            key=lambda fact: (
                *_hop_fact_weight(fact),
                int(fact.get("source_measurement_id") or fact.get("measurement_id") or 0),
            ),
            reverse=True,
        )
        resolved.append(candidates[0])
    return resolved


def _resolved_hop_facts_for_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    hop_facts = report.get("hop_facts")
    if isinstance(hop_facts, list) and hop_facts:
        return resolve_best_hop_facts([hop for hop in hop_facts if isinstance(hop, dict)])
    hops = report.get("hops")
    if isinstance(hops, list):
        # Legacy synthetic reports still expose `hops`; treat them as already resolved.
        return [hop for hop in hops if isinstance(hop, dict)]
    return []


def save_route_memory_report(report: dict[str, Any], *, source_node: str | None = None, graph_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized_source = _ensure_text(source_node or report.get("source_node"), "unknown")
    observation_uid = _observation_uid(normalized_source, report)
    hop_rows = list(report.get("observed_segments") or [])
    match_rows = list(report.get("segment_matches") or [])
    event_rows = list(report.get("route_memory_events") or [])
    existing = _fetch_observation(observation_uid)
    if existing is not None:
        counts = _existing_child_counts(observation_uid)
        existing_hops = _existing_hop_fact_keys(observation_uid) if counts["hop_facts"] > 0 else set()
        inserted = False
        hop_facts_inserted = 0
        segments_inserted = 0
        matches_inserted = 0
        events_inserted = 0
        graph_snapshot_inserted = False
        with get_connection() as conn:
            with conn.cursor() as cur:
                hop_facts_inserted = _insert_hop_facts(cur, observation_uid, normalized_source, report, existing_hops=existing_hops)
                inserted = inserted or hop_facts_inserted > 0
                if counts["segments"] == 0:
                    observed_segments = _insert_segments(cur, observation_uid, normalized_source, report)
                    segments_inserted = len(observed_segments)
                    matches_inserted = _insert_matches(cur, observation_uid, observed_segments, report)
                    events_inserted = _insert_events(cur, observation_uid, normalized_source, report, observed_segments)
                    inserted = inserted or segments_inserted > 0 or matches_inserted > 0 or events_inserted > 0
                if graph_payload is not None:
                    graph_snapshot_inserted = _insert_graph_snapshot(cur, normalized_source, [observation_uid], graph_payload, report)
                    inserted = inserted or graph_snapshot_inserted
                if inserted:
                    conn.commit()
        return {
            "observation_uid": observation_uid,
            "observation_id": existing["id"],
            "inserted": False,
            "segments_inserted": segments_inserted,
            "hop_facts_inserted": hop_facts_inserted,
            "matches_inserted": matches_inserted,
            "events_inserted": events_inserted,
            "graph_snapshot_inserted": graph_snapshot_inserted,
        }

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into route_memory_observations (
                    observation_uid,
                    source_node,
                    target,
                    resolved_ip,
                    tool,
                    observed_at,
                    route_memory_version,
                    knowledge_status,
                    route_known_fraction,
                    summary,
                    raw_input_ref,
                    report_json
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
                returning id;
                """,
                (
                    observation_uid,
                    normalized_source,
                    report.get("target"),
                    report.get("resolved_ip"),
                    report.get("tool"),
                    report.get("observed_at"),
                    _route_memory_version(report),
                    report.get("knowledge_status"),
                    report.get("route_known_fraction"),
                    report.get("summary") or report.get("next_recommended_action"),
                    json.dumps(_json_safe(report.get("raw_input_ref")), ensure_ascii=False),
                    json.dumps(_json_safe(report), ensure_ascii=False),
                ),
            )
            observation_id = cur.fetchone()[0]
            segments_inserted = _insert_hop_facts(cur, observation_uid, normalized_source, report)
            observed_segments = _insert_segments(cur, observation_uid, normalized_source, report)
            matches_inserted = _insert_matches(cur, observation_uid, observed_segments, report)
            events_inserted = _insert_events(cur, observation_uid, normalized_source, report, observed_segments)
            graph_snapshot_inserted = False
            if graph_payload is not None:
                graph_snapshot_inserted = _insert_graph_snapshot(cur, normalized_source, [observation_uid], graph_payload, report)
            conn.commit()
    return {
        "observation_uid": observation_uid,
        "observation_id": observation_id,
        "inserted": True,
        "segments_inserted": len(observed_segments),
        "hop_facts_inserted": segments_inserted,
        "matches_inserted": matches_inserted,
        "events_inserted": events_inserted,
        "graph_snapshot_inserted": graph_snapshot_inserted,
    }


def _fetch_observation(observation_uid: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select id, observation_uid, report_json from route_memory_observations where observation_uid = %s limit 1;", (observation_uid,))
            row = cur.fetchone()
            return dict(row) if row else None


def fetch_latest_route_memory_graph_snapshot() -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    graph_uid,
                    schema_version,
                    source_node,
                    title,
                    graph_type,
                    route_count,
                    created_at,
                    payload_json
                from route_memory_graph_snapshots
                order by created_at desc, id desc
                limit 1;
                """
            )
            row = cur.fetchone()
            if row is None:
                return None
            snapshot = dict(row)
            snapshot["payload"] = snapshot.pop("payload_json")
            return snapshot


def fetch_route_memory_graph_snapshot(graph_uid: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select
                    graph_uid,
                    schema_version,
                    source_node,
                    title,
                    graph_type,
                    route_count,
                    created_at,
                    payload_json
                from route_memory_graph_snapshots
                where graph_uid = %s
                limit 1;
                """,
                (graph_uid,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            snapshot = dict(row)
            snapshot["payload"] = snapshot.pop("payload_json")
            return snapshot


def load_route_memory_report(observation_uid: str) -> dict[str, Any] | None:
    observation = _fetch_observation(observation_uid)
    if not observation:
        return None
    report = observation.get("report_json")
    if isinstance(report, dict):
        return report
    return None


def _existing_child_counts(observation_uid: str) -> dict[str, int]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            counts: dict[str, int] = {}
            for table, key in [
                ("route_memory_hop_facts", "hop_facts"),
                ("route_memory_segments_observed", "segments"),
                ("route_memory_segment_matches", "matches"),
                ("route_memory_events", "events"),
                ("route_memory_graph_snapshots", "graph_snapshots"),
            ]:
                if table == "route_memory_graph_snapshots":
                    cur.execute("select count(*)::int as value from route_memory_graph_snapshots where %s = any(observation_uids);", (observation_uid,))
                else:
                    cur.execute(f"select count(*)::int as value from {table} where observation_uid = %s;", (observation_uid,))
                row = cur.fetchone()
                counts[key] = int(row["value"]) if row else 0
            return counts


def _existing_hop_fact_keys(observation_uid: str) -> set[tuple[int | None, str | None]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select hop_index, ip::text as ip
                from route_memory_hop_facts
                where observation_uid = %s;
                """,
                (observation_uid,),
            )
            return {
                (int(row["hop_index"]) if row["hop_index"] is not None else None, row["ip"])
                for row in cur.fetchall()
            }


def _insert_hop_facts(
    cur: Any,
    observation_uid: str,
    source_node: str,
    report: dict[str, Any],
    *,
    existing_hops: set[tuple[int | None, str | None]] | None = None,
) -> int:
    count = 0
    existing_hops = existing_hops or set()
    hop_source_rows = _resolved_hop_facts_for_report(report)
    for index, hop in enumerate(hop_source_rows, start=1):
        if not isinstance(hop, dict):
            continue
        hop_index = int(hop.get("hop_index", index)) if hop.get("hop_index", index) is not None else index
        hop_ip = hop.get("ip")
        if (hop_index, hop_ip) in existing_hops:
            continue
        cur.execute(
            """
            insert into route_memory_hop_facts (
                observation_uid,
                hop_index,
                ip,
                raw_host,
                hop_type,
                is_silent,
                is_private,
                is_public,
                is_destination,
                loss_percent,
                avg_ms,
                reverse_dns,
                rdns_domain,
                bgp_prefix,
                origin_asn,
                as_path,
                confidence,
                evidence
            )
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb);
            """,
            (
                observation_uid,
                hop_index,
                hop_ip,
                hop.get("raw_host"),
                hop.get("hop_type"),
                bool(hop.get("is_silent", False)),
                bool(hop.get("is_private", False)),
                bool(hop.get("is_public", False)),
                bool(hop.get("is_destination", False)),
                hop.get("loss_percent"),
                hop.get("avg_ms"),
                hop.get("reverse_dns"),
                hop.get("rdns_domain"),
                hop.get("bgp_prefix"),
                hop.get("origin_asn"),
                hop.get("as_path"),
                hop.get("confidence"),
                json.dumps(_json_safe(hop.get("evidence")), ensure_ascii=False),
            ),
        )
        count += 1
    return count


def _insert_segments(cur: Any, observation_uid: str, source_node: str, report: dict[str, Any]) -> list[dict[str, Any]]:
    inserted: list[dict[str, Any]] = []
    for segment_index, segment in enumerate(report.get("observed_segments") or [], start=1):
        if not isinstance(segment, dict):
            continue
        observed_segment_uid = _segment_uid(observation_uid, segment)
        row = {
            "observed_segment_uid": observed_segment_uid,
            "segment_index": segment_index,
            "segment_type": segment.get("segment_type"),
            "start_hop": segment.get("start_hop"),
            "end_hop": segment.get("end_hop"),
            "hop_count": segment.get("hop_count"),
            "contains_private": bool(segment.get("contains_private", False)),
            "contains_public": bool(segment.get("contains_public", False)),
            "contains_silent": bool(segment.get("contains_silent", False)),
            "contains_mpls": bool(segment.get("contains_mpls", False)),
            "context_asn": segment.get("context_asn"),
            "first_public_asn": segment.get("first_public_asn"),
            "last_public_asn": segment.get("last_public_asn"),
            "next_public_asn": segment.get("next_public_asn"),
            "previous_public_asn": segment.get("previous_public_asn"),
            "rdns_signature": segment.get("rdns_signature"),
            "exact_fingerprint": segment.get("exact_fingerprint"),
            "structural_fingerprint": segment.get("structural_fingerprint"),
            "confidence": segment.get("confidence"),
            "state": segment.get("state") or "observed",
            "human_summary": segment.get("human_summary"),
            "evidence": segment.get("evidence"),
        }
        cur.execute(
            """
            insert into route_memory_segments_observed (
                observed_segment_uid,
                observation_uid,
                source_node,
                segment_index,
                segment_type,
                start_hop,
                end_hop,
                hop_count,
                contains_private,
                contains_public,
                contains_silent,
                contains_mpls,
                context_asn,
                first_public_asn,
                last_public_asn,
                next_public_asn,
                previous_public_asn,
                rdns_signature,
                exact_fingerprint,
                structural_fingerprint,
                confidence,
                state,
                human_summary,
                evidence
            )
            values (
                %(observed_segment_uid)s,
                %(observation_uid)s,
                %(source_node)s,
                %(segment_index)s,
                %(segment_type)s,
                %(start_hop)s,
                %(end_hop)s,
                %(hop_count)s,
                %(contains_private)s,
                %(contains_public)s,
                %(contains_silent)s,
                %(contains_mpls)s,
                %(context_asn)s,
                %(first_public_asn)s,
                %(last_public_asn)s,
                %(next_public_asn)s,
                %(previous_public_asn)s,
                %(rdns_signature)s,
                %(exact_fingerprint)s,
                %(structural_fingerprint)s,
                %(confidence)s,
                %(state)s,
                %(human_summary)s,
                %(evidence)s::jsonb
            );
            """,
            {
                **row,
                "observation_uid": observation_uid,
                "source_node": source_node,
                "evidence": json.dumps(_json_safe(row["evidence"]), ensure_ascii=False),
            },
        )
        inserted.append({"observed_segment_uid": observed_segment_uid, **row})
    return inserted


def _insert_matches(cur: Any, observation_uid: str, observed_segments: list[dict[str, Any]], report: dict[str, Any]) -> int:
    count = 0
    matches = list(report.get("segment_matches") or [])
    for segment, match in zip(observed_segments, matches):
        if not isinstance(match, dict):
            continue
        match_uid = _match_uid(observation_uid, segment["observed_segment_uid"], match)
        cur.execute(
            """
            insert into route_memory_segment_matches (
                match_uid,
                observation_uid,
                observed_segment_uid,
                matched_observed_segment_uid,
                matched_known_segment_uid,
                match_type,
                match_score,
                matched_hops_count,
                divergence_hop,
                divergence_type,
                decision,
                confidence,
                evidence,
                explanation
            )
            values (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s
            );
            """,
            (
                match_uid,
                observation_uid,
                segment["observed_segment_uid"],
                match.get("observed_segment_uid"),
                match.get("known_segment_id") or match.get("matched_known_segment_uid"),
                match.get("match_type"),
                match.get("match_score"),
                match.get("matched_hops_count"),
                match.get("divergence_hop"),
                match.get("divergence_type"),
                match.get("decision"),
                match.get("confidence"),
                json.dumps(_json_safe(match.get("evidence")), ensure_ascii=False),
                match.get("explanation"),
            ),
        )
        count += 1
    return count


def _insert_events(cur: Any, observation_uid: str, source_node: str, report: dict[str, Any], observed_segments: list[dict[str, Any]]) -> int:
    count = 0
    for event in report.get("route_memory_events") or []:
        if not isinstance(event, dict):
            continue
        event_uid = _event_uid(observation_uid, event)
        cur.execute(
            """
            insert into route_memory_events (
                event_uid,
                source_node,
                observation_uid,
                observed_segment_uid,
                event_type,
                severity,
                old_value,
                new_value,
                explanation,
                evidence
            )
            values (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s::jsonb);
            """,
            (
                event_uid,
                source_node,
                observation_uid,
                event.get("observed_segment_uid"),
                event.get("event_type"),
                event.get("severity"),
                json.dumps(_json_safe(event.get("old_value")), ensure_ascii=False),
                json.dumps(_json_safe(event.get("new_value")), ensure_ascii=False),
                event.get("explanation"),
                json.dumps(_json_safe(event.get("evidence")), ensure_ascii=False),
            ),
        )
        count += 1
    return count


def _insert_graph_snapshot(cur: Any, source_node: str, observation_uids: list[str], payload: dict[str, Any], report: dict[str, Any]) -> bool:
    graph_uid = _stable_uid(
        "rmg",
        source_node,
        *observation_uids,
        payload.get("schema") or payload.get("schema_version"),
        _payload_fingerprint(payload),
    )
    cur.execute("select 1 from route_memory_graph_snapshots where graph_uid = %s limit 1;", (graph_uid,))
    if cur.fetchone():
        return False
    cur.execute(
        """
        insert into route_memory_graph_snapshots (
            graph_uid,
            source_node,
            title,
            graph_type,
            route_count,
            observation_uids,
            schema_version,
            payload_json
        )
        values (%s, %s, %s, %s, %s, %s, %s, %s::jsonb);
        """,
        (
            graph_uid,
            source_node,
            payload.get("title") or report.get("summary"),
            payload.get("graph_type") or "route_memory_graph",
            payload.get("route_count") or len(payload.get("routes") or []),
            observation_uids,
            payload.get("schema") or payload.get("schema_version") or "route_memory_graph.v1",
            json.dumps(_json_safe(payload), ensure_ascii=False),
        ),
    )
    return True
