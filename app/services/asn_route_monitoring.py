from __future__ import annotations

from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.db.connection import get_connection
from app.services.bgp_operational_queries import get_asn_lookup


DB_ERROR_MESSAGE = "Erro ao consultar o PostgreSQL do RouteBrain."
DEFAULT_LIMITS = {
    "route_limit": 1000,
    "prefix_limit": 500,
    "peer_limit": 100,
    "prefix_peer_pair_limit": 2000,
    "as_path_limit": 200,
}


def _fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def _fetch_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    try:
        with get_connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                row = cur.fetchone()
                return dict(row) if row is not None else None
    except psycopg.Error as exc:
        raise RuntimeError(DB_ERROR_MESSAGE) from exc


def _json(value: Any) -> Json:
    return Json(value)


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _normalize_asn(asn: int | str) -> int:
    try:
        normalized = int(str(asn).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("ASN inválido.") from exc
    if normalized < 0:
        raise ValueError("ASN inválido.")
    return normalized


def _limits(overrides: dict[str, int] | None = None) -> dict[str, int]:
    limits = dict(DEFAULT_LIMITS)
    if overrides:
        for key, value in overrides.items():
            try:
                limits[key] = max(1, int(value))
            except (TypeError, ValueError):
                continue
    return limits


def _unique_rows(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    output: list[dict[str, Any]] = []
    for row in rows:
        marker = tuple(row.get(key) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        output.append(row)
    return output


def _route_signature(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("prefix") or "").strip(), str(row.get("peer_ip") or "").strip())


def _group_routes_by_prefix(routes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in routes:
        prefix = str(row.get("prefix") or "").strip()
        if not prefix:
            continue
        grouped.setdefault(prefix, []).append(row)
    return grouped


def _group_routes_by_peer(routes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in routes:
        peer_ip = str(row.get("peer_ip") or "").strip()
        if not peer_ip:
            continue
        grouped.setdefault(peer_ip, []).append(row)
    return grouped


def _normalize_route_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": row.get("source"),
        "collector": row.get("collector"),
        "peer_ip": str(row.get("peer_ip") or "").strip() or None,
        "peer_asn": row.get("peer_asn"),
        "prefix": str(row.get("prefix") or "").strip() or None,
        "next_hop": row.get("next_hop"),
        "as_path": str(row.get("as_path") or "").strip() or None,
        "origin_asn": row.get("origin_asn"),
        "origin_type": row.get("origin_type"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
    }


def _current_lookup(asn: int) -> dict[str, Any]:
    lookup = get_asn_lookup(asn, limit=200) or {}
    summary = lookup.get("summary") or {}
    prefixes = lookup.get("prefixes") or []
    top_peers = lookup.get("top_peers") or []
    current_routes = lookup.get("current_routes") or []
    recent_changes = lookup.get("recent_changes") or []
    change_distribution = lookup.get("change_distribution") or []
    sample_prefixes: list[str] = []
    seen: set[str] = set()
    for row in prefixes:
        if not isinstance(row, dict):
            continue
        prefix = str(row.get("prefix") or "").strip()
        if prefix and prefix not in seen:
            seen.add(prefix)
            sample_prefixes.append(prefix)
    if not sample_prefixes:
        for row in current_routes:
            if not isinstance(row, dict):
                continue
            prefix = str(row.get("prefix") or "").strip()
            if prefix and prefix not in seen:
                seen.add(prefix)
                sample_prefixes.append(prefix)
            if len(sample_prefixes) >= 5:
                break
    sample_as_paths: list[str] = []
    seen_paths: set[str] = set()
    for row in current_routes:
        if not isinstance(row, dict):
            continue
        as_path = str(row.get("as_path") or "").strip()
        if not as_path or as_path in seen_paths:
            continue
        seen_paths.add(as_path)
        sample_as_paths.append(as_path)
        if len(sample_as_paths) >= 20:
            break
    return {
        "lookup": lookup,
        "summary": summary,
        "prefixes": prefixes,
        "top_peers": top_peers,
        "current_routes": current_routes,
        "recent_changes": recent_changes,
        "change_distribution": change_distribution,
        "sample_prefixes": sample_prefixes[:5],
        "sample_as_paths": sample_as_paths,
    }


def build_current_asn_snapshot(asn: int | str, limits: dict[str, int] | None = None) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    limit_cfg = _limits(limits)
    lookup = get_asn_lookup(normalized_asn, limit=limit_cfg["route_limit"]) or {}
    summary = lookup.get("summary") or {}
    prefixes = lookup.get("prefixes") or []
    top_peers = lookup.get("top_peers") or []
    current_routes = lookup.get("current_routes") or []
    route_count = int(summary.get("total_current_routes") or len(current_routes) or 0)
    prefix_count = int(summary.get("total_prefixes") or len(prefixes) or 0)
    peer_count = int(summary.get("total_peers") or len(top_peers) or 0)

    normalized_routes = [_normalize_route_row(row) for row in current_routes if isinstance(row, dict)]
    normalized_routes = [row for row in normalized_routes if row.get("prefix") and row.get("peer_ip")]
    normalized_routes = _unique_rows(normalized_routes, ("prefix", "peer_ip", "collector", "as_path"))

    peers: list[dict[str, Any]] = []
    for row in top_peers[: limit_cfg["peer_limit"]]:
        peers.append(
            {
                "peer_ip": str(row.get("peer_ip") or "").strip() or None,
                "peer_asn": row.get("peer_asn"),
                "route_count": int(row.get("total_routes") or 0),
                "prefix_count": int(row.get("total_prefixes") or 0),
            }
        )

    top_prefixes: list[dict[str, Any]] = []
    for row in prefixes[: limit_cfg["prefix_limit"]]:
        top_prefixes.append(
            {
                "prefix": str(row.get("prefix") or "").strip() or None,
                "peer_count": int(row.get("total_peers") or 0),
                "route_count": int(row.get("total_routes") or 0),
            }
        )

    prefix_peer_pairs: list[dict[str, Any]] = []
    for row in normalized_routes[: limit_cfg["prefix_peer_pair_limit"]]:
        prefix_peer_pairs.append(
            {
                "prefix": row.get("prefix"),
                "peer_ip": row.get("peer_ip"),
                "collector": row.get("collector"),
                "as_path": row.get("as_path"),
                "origin_asn": row.get("origin_asn"),
            }
        )

    sample_as_paths: list[str] = []
    seen_paths: set[str] = set()
    for row in normalized_routes:
        as_path = str(row.get("as_path") or "").strip()
        if not as_path or as_path in seen_paths:
            continue
        seen_paths.add(as_path)
        sample_as_paths.append(as_path)
        if len(sample_as_paths) >= limit_cfg["as_path_limit"]:
            break

    peers_by_ip = {}
    for row in peers:
        peer_ip = row.get("peer_ip")
        if peer_ip:
            peers_by_ip[str(peer_ip)] = row

    prefixes_by_name = {}
    for row in top_prefixes:
        prefix = row.get("prefix")
        if prefix:
            prefixes_by_name[str(prefix)] = row

    return {
        "asn": normalized_asn,
        "snapshot_at": datetime.now().astimezone().isoformat(),
        "route_count": route_count,
        "prefix_count": prefix_count,
        "peer_count": peer_count,
        "summary": {
            "route_count": route_count,
            "prefix_count": prefix_count,
            "peer_count": peer_count,
            "total_peer_asns": int(summary.get("total_peer_asns") or 0),
            "total_collectors": int(summary.get("total_collectors") or 0),
            "first_seen_min": summary.get("first_seen_min"),
            "last_seen_max": summary.get("last_seen_max"),
            "limits": limit_cfg,
        },
        "peers": peers,
        "top_prefixes": top_prefixes,
        "prefix_peer_pairs": prefix_peer_pairs,
        "sample_as_paths": sample_as_paths,
        "limits": limit_cfg,
        "lookup": lookup,
        "lookups": {
            "peers_by_ip": peers_by_ip,
            "prefixes_by_name": prefixes_by_name,
        },
    }


def get_latest_asn_snapshot(asn: int | str) -> dict[str, Any] | None:
    normalized_asn = _normalize_asn(asn)
    snapshot = _fetch_one(
        """
        select
          id,
          asn,
          snapshot_at,
          current_route_count,
          prefix_count,
          peer_count,
          sample_prefixes,
          summary
        from asn_route_monitoring_snapshots
        where asn = %s
        order by snapshot_at desc, id desc
        limit 1;
        """,
        (normalized_asn,),
    )
    if snapshot is None:
        return None
    summary = snapshot.get("summary") or {}
    if not isinstance(summary, dict):
        summary = {}
    route_count = int(snapshot.get("current_route_count") or summary.get("route_count") or summary.get("total_current_routes") or 0)
    prefix_count = int(snapshot.get("prefix_count") or summary.get("prefix_count") or summary.get("total_prefixes") or 0)
    peer_count = int(snapshot.get("peer_count") or summary.get("peer_count") or summary.get("total_peers") or 0)
    return {
        **snapshot,
        "summary": summary,
        "route_count": route_count,
        "prefix_count": prefix_count,
        "peer_count": peer_count,
        "peers": summary.get("peers") or [],
        "top_prefixes": summary.get("top_prefixes") or [],
        "prefix_peer_pairs": summary.get("prefix_peer_pairs") or [],
        "sample_as_paths": summary.get("sample_as_paths") or [],
        "limits": summary.get("limits") or {},
    }


def compare_asn_snapshots(baseline_snapshot: dict[str, Any], current_snapshot: dict[str, Any]) -> dict[str, Any]:
    baseline_routes = baseline_snapshot.get("prefix_peer_pairs") or []
    current_routes = current_snapshot.get("prefix_peer_pairs") or []
    baseline_prefixes = baseline_snapshot.get("top_prefixes") or []
    current_prefixes = current_snapshot.get("top_prefixes") or []
    baseline_peers = baseline_snapshot.get("peers") or []
    current_peers = current_snapshot.get("peers") or []

    baseline_route_count = int(baseline_snapshot.get("route_count") or 0)
    current_route_count = int(current_snapshot.get("route_count") or 0)
    baseline_prefix_count = int(baseline_snapshot.get("prefix_count") or 0)
    current_prefix_count = int(current_snapshot.get("prefix_count") or 0)
    baseline_peer_count = int(baseline_snapshot.get("peer_count") or 0)
    current_peer_count = int(current_snapshot.get("peer_count") or 0)

    baseline_prefix_names = {str(row.get("prefix") or "").strip() for row in baseline_prefixes if row.get("prefix")}
    current_prefix_names = {str(row.get("prefix") or "").strip() for row in current_prefixes if row.get("prefix")}
    baseline_peer_names = {str(row.get("peer_ip") or "").strip() for row in baseline_peers if row.get("peer_ip")}
    current_peer_names = {str(row.get("peer_ip") or "").strip() for row in current_peers if row.get("peer_ip")}

    baseline_peer_map = {}
    for row in baseline_peers:
        peer_ip = str(row.get("peer_ip") or "").strip()
        if peer_ip:
            baseline_peer_map[peer_ip] = row
    current_peer_map = {}
    for row in current_peers:
        peer_ip = str(row.get("peer_ip") or "").strip()
        if peer_ip:
            current_peer_map[peer_ip] = row

    baseline_route_map = {}
    for row in baseline_routes:
        baseline_route_map[_route_signature(row)] = row
    current_route_map = {}
    for row in current_routes:
        current_route_map[_route_signature(row)] = row

    baseline_routes_by_prefix = _group_routes_by_prefix(baseline_routes)
    current_routes_by_prefix = _group_routes_by_prefix(current_routes)
    baseline_routes_by_peer = _group_routes_by_peer(baseline_routes)
    current_routes_by_peer = _group_routes_by_peer(current_routes)

    added_prefixes = sorted(current_prefix_names - baseline_prefix_names)
    removed_prefixes = sorted(baseline_prefix_names - current_prefix_names)
    added_peers = sorted(current_peer_names - baseline_peer_names)
    removed_peers = sorted(baseline_peer_names - current_peer_names)

    changed_prefix_peers: list[dict[str, Any]] = []
    for prefix in sorted(baseline_prefix_names & current_prefix_names):
        baseline_prefix_peers = {str(row.get("peer_ip") or "").strip() for row in baseline_routes_by_prefix.get(prefix, []) if row.get("peer_ip")}
        current_prefix_peers = {str(row.get("peer_ip") or "").strip() for row in current_routes_by_prefix.get(prefix, []) if row.get("peer_ip")}
        if baseline_prefix_peers != current_prefix_peers:
            changed_prefix_peers.append(
                {
                    "prefix": prefix,
                    "baseline_peer_count": len(baseline_prefix_peers),
                    "current_peer_count": len(current_prefix_peers),
                    "added_peers": sorted(current_prefix_peers - baseline_prefix_peers)[:10],
                    "removed_peers": sorted(baseline_prefix_peers - current_prefix_peers)[:10],
                }
            )

    peer_route_count_changes: list[dict[str, Any]] = []
    for peer_ip in sorted(baseline_peer_names & current_peer_names):
        baseline_row = baseline_peer_map.get(peer_ip) or {}
        current_row = current_peer_map.get(peer_ip) or {}
        baseline_count = int(baseline_row.get("route_count") or baseline_row.get("total_routes") or 0)
        current_count = int(current_row.get("route_count") or current_row.get("total_routes") or 0)
        delta = current_count - baseline_count
        if delta:
            peer_route_count_changes.append(
                {
                    "peer_ip": peer_ip,
                    "peer_asn": current_row.get("peer_asn") or baseline_row.get("peer_asn"),
                    "route_count_delta": delta,
                    "baseline_route_count": baseline_count,
                    "current_route_count": current_count,
                    "baseline_prefix_count": int(baseline_row.get("prefix_count") or baseline_row.get("total_prefixes") or 0),
                    "current_prefix_count": int(current_row.get("prefix_count") or current_row.get("total_prefixes") or 0),
                }
            )
    peer_route_count_changes.sort(key=lambda item: (abs(int(item.get("route_count_delta") or 0)), str(item.get("peer_ip") or "")), reverse=True)

    as_path_changes: list[dict[str, Any]] = []
    as_path_supported = bool(current_snapshot.get("sample_as_paths") or baseline_snapshot.get("sample_as_paths") or current_route_map or baseline_route_map)
    for key in sorted(set(baseline_route_map) & set(current_route_map)):
        baseline_row = baseline_route_map.get(key) or {}
        current_row = current_route_map.get(key) or {}
        baseline_as_path = str(baseline_row.get("as_path") or "").strip()
        current_as_path = str(current_row.get("as_path") or "").strip()
        if baseline_as_path and current_as_path and baseline_as_path != current_as_path:
            as_path_changes.append(
                {
                    "prefix": current_row.get("prefix") or baseline_row.get("prefix"),
                    "peer_ip": current_row.get("peer_ip") or baseline_row.get("peer_ip"),
                    "collector": current_row.get("collector") or baseline_row.get("collector"),
                    "baseline_as_path": baseline_as_path,
                    "current_as_path": current_as_path,
                }
            )
    as_path_changes = as_path_changes[:25]
    if not as_path_changes and not (current_snapshot.get("sample_as_paths") or baseline_snapshot.get("sample_as_paths")):
        as_path_supported = False

    route_count_delta = current_route_count - baseline_route_count
    prefix_count_delta = current_prefix_count - baseline_prefix_count
    peer_count_delta = current_peer_count - baseline_peer_count
    change_detected = bool(
        route_count_delta
        or prefix_count_delta
        or peer_count_delta
        or added_prefixes
        or removed_prefixes
        or changed_prefix_peers
        or added_peers
        or removed_peers
        or peer_route_count_changes
        or as_path_changes
    )

    confidence = "high"
    reasons: list[str] = []
    if not baseline_snapshot or not current_snapshot:
        confidence = "inconclusive"
        reasons.append("missing_snapshot")
    if not baseline_snapshot.get("prefix_peer_pairs") or not current_snapshot.get("prefix_peer_pairs"):
        confidence = "low" if confidence != "inconclusive" else confidence
        reasons.append("limited_prefix_peer_pairs")
    if not as_path_supported:
        confidence = "medium" if confidence == "high" else confidence
        reasons.append("as_path_unavailable")
    if not change_detected and confidence != "inconclusive":
        confidence = "medium" if reasons else "high"

    if not baseline_snapshot or not baseline_snapshot.get("prefix_peer_pairs"):
        confidence = "inconclusive"
    if current_prefix_count == 0 and current_peer_count == 0 and current_route_count == 0:
        reasons.append("current_snapshot_empty")
        if confidence != "inconclusive":
            confidence = "low"
    if not baseline_routes or not current_routes:
        reasons.append("limited_route_pairs")
        if confidence != "inconclusive" and confidence != "low":
            confidence = "medium"

    reason = "diff_available" if change_detected else "no_clear_difference"
    if confidence == "inconclusive":
        reason = "insufficient_baseline_comparison"
    elif not change_detected:
        reason = "no_relevant_change_detected"
    elif reasons:
        reason = ";".join(sorted(set(reasons)))

    return {
        "baseline_exists": True,
        "baseline_snapshot_at": baseline_snapshot.get("snapshot_at"),
        "current_snapshot_at": current_snapshot.get("snapshot_at"),
        "baseline_route_count": baseline_route_count,
        "current_route_count": current_route_count,
        "route_count_delta": route_count_delta,
        "baseline_prefix_count": baseline_prefix_count,
        "current_prefix_count": current_prefix_count,
        "prefix_count_delta": prefix_count_delta,
        "baseline_peer_count": baseline_peer_count,
        "current_peer_count": current_peer_count,
        "peer_count_delta": peer_count_delta,
        "added_prefixes": added_prefixes[:10],
        "removed_prefixes": removed_prefixes[:10],
        "changed_prefix_peers": changed_prefix_peers[:10],
        "added_peers": added_peers[:10],
        "removed_peers": removed_peers[:10],
        "peer_route_count_changes": peer_route_count_changes[:10],
        "as_path_changes_supported": as_path_supported,
        "as_path_changes": as_path_changes[:10],
        "change_detected": change_detected,
        "confidence": confidence,
        "reason": reason,
        "limitations": sorted(set(reasons)) if reasons else [],
    }


def get_asn_monitoring_status(asn: int | str) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    target = _fetch_one(
        """
        select
          id,
          asn,
          label,
          status,
          reason,
          created_at,
          updated_at,
          created_from_request_uid,
          baseline_status,
          baseline_started_at,
          baseline_last_checked_at,
          notes
        from asn_route_monitoring_targets
        where asn = %s
        limit 1;
        """,
        (normalized_asn,),
    )
    snapshots = _fetch_all(
        """
        select
          id,
          asn,
          snapshot_at,
          current_route_count,
          prefix_count,
          peer_count,
          sample_prefixes,
          summary
        from asn_route_monitoring_snapshots
        where asn = %s
        order by snapshot_at desc, id desc;
        """,
        (normalized_asn,),
    )
    current = _current_lookup(normalized_asn)
    return {
        "asn": normalized_asn,
        "target": target,
        "snapshots": snapshots,
        "current": current,
    }


def add_asn_monitoring_target(
    asn: int | str,
    label: str | None = None,
    reason: str | None = None,
    request_uid: str | None = None,
) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    now = datetime.now().astimezone()
    current = _current_lookup(normalized_asn)
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into asn_route_monitoring_targets (
                  asn, label, status, reason, created_from_request_uid,
                  baseline_status, baseline_started_at, baseline_last_checked_at, notes
                )
                values (%s, %s, 'monitoring', %s, %s, 'pending', %s, %s, %s)
                on conflict (asn)
                do update set
                  label = coalesce(excluded.label, asn_route_monitoring_targets.label),
                  status = 'monitoring',
                  reason = coalesce(excluded.reason, asn_route_monitoring_targets.reason),
                  created_from_request_uid = coalesce(excluded.created_from_request_uid, asn_route_monitoring_targets.created_from_request_uid),
                  baseline_status = case
                    when asn_route_monitoring_targets.baseline_status in ('pending', 'missing') then 'pending'
                    else asn_route_monitoring_targets.baseline_status
                  end,
                  baseline_started_at = coalesce(asn_route_monitoring_targets.baseline_started_at, excluded.baseline_started_at),
                  baseline_last_checked_at = excluded.baseline_last_checked_at,
                  notes = coalesce(asn_route_monitoring_targets.notes, '{}'::jsonb) || excluded.notes,
                  updated_at = now()
                returning
                  id, asn, label, status, reason, created_at, updated_at, created_from_request_uid,
                  baseline_status, baseline_started_at, baseline_last_checked_at, notes;
                """,
                (
                    normalized_asn,
                    label,
                    reason,
                    request_uid,
                    now,
                    now,
                    _json(_safe_json({"initial_snapshot": current["summary"], "sample_prefixes": current["sample_prefixes"]})),
                ),
            )
            target = dict(cur.fetchone() or {})
            cur.execute(
                """
                update asn_route_monitoring_targets
                set baseline_last_checked_at = now(),
                    updated_at = now()
                where asn = %s;
                """,
                (normalized_asn,),
            )
    return {
        "target": target,
        "current": current,
    }


def ensure_asn_monitoring_target(
    asn: int | str,
    label: str | None = None,
    reason: str | None = None,
    request_uid: str | None = None,
) -> dict[str, Any]:
    status = get_asn_monitoring_status(asn)
    if status.get("target"):
        return status
    add_asn_monitoring_target(asn, label=label, reason=reason, request_uid=request_uid)
    return get_asn_monitoring_status(asn)


def record_asn_snapshot(
    asn: int | str,
    *,
    reason: str | None = None,
    request_uid: str | None = None,
) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    ensure_asn_monitoring_target(asn, reason=reason, request_uid=request_uid)
    current_snapshot = build_current_asn_snapshot(normalized_asn)
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                insert into asn_route_monitoring_snapshots (
                  asn, snapshot_at, current_route_count, prefix_count, peer_count, sample_prefixes, summary
                )
                values (%s, now(), %s, %s, %s, %s, %s)
                returning id, asn, snapshot_at, current_route_count, prefix_count, peer_count, sample_prefixes, summary;
                """,
                (
                    normalized_asn,
                    int(current_snapshot.get("route_count") or 0),
                    int(current_snapshot.get("prefix_count") or 0),
                    int(current_snapshot.get("peer_count") or 0),
                    _json(_safe_json(current_snapshot.get("top_prefixes") or [])),
                    _json(_safe_json(
                        {
                            "route_count": current_snapshot.get("route_count"),
                            "prefix_count": current_snapshot.get("prefix_count"),
                            "peer_count": current_snapshot.get("peer_count"),
                            "summary": current_snapshot.get("summary"),
                            "peers": current_snapshot.get("peers"),
                            "top_prefixes": current_snapshot.get("top_prefixes"),
                            "prefix_peer_pairs": current_snapshot.get("prefix_peer_pairs"),
                            "sample_as_paths": current_snapshot.get("sample_as_paths"),
                            "limits": current_snapshot.get("limits"),
                        }
                    )),
                ),
            )
            snapshot = dict(cur.fetchone() or {})
            cur.execute(
                """
                update asn_route_monitoring_targets
                set baseline_status = case
                        when baseline_status = 'pending' then 'started'
                        else baseline_status
                    end,
                    baseline_started_at = coalesce(baseline_started_at, now()),
                    baseline_last_checked_at = now(),
                    updated_at = now()
                where asn = %s
                returning asn, label, status, reason, baseline_status, baseline_started_at, baseline_last_checked_at, notes;
                """,
                (normalized_asn,),
            )
            target = dict(cur.fetchone() or {})
    return {"target": target, "snapshot": snapshot, "current": current_snapshot}


def get_asn_baseline_summary(asn: int | str) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    state = get_asn_monitoring_status(normalized_asn)
    target = state.get("target") or {}
    snapshots = state.get("snapshots") or []
    current = state.get("current") or {}
    latest_snapshot = get_latest_asn_snapshot(normalized_asn)
    baseline_exists = latest_snapshot is not None
    baseline_status = str((target or {}).get("baseline_status") or ("pending" if not baseline_exists else "started"))
    current_summary = current.get("summary") or {}
    current_route_count = int(current_summary.get("total_current_routes") or 0)
    current_prefix_count = int(current_summary.get("total_prefixes") or 0)
    current_peer_count = int(current_summary.get("total_peers") or 0)
    if latest_snapshot:
        snapshot_prefixes = [row.get("prefix") for row in (latest_snapshot.get("top_prefixes") or []) if row.get("prefix")][:20]
        baseline_route_count = int(latest_snapshot.get("route_count") or 0)
        baseline_prefix_count = int(latest_snapshot.get("prefix_count") or 0)
        baseline_peer_count = int(latest_snapshot.get("peer_count") or 0)
    else:
        snapshot_prefixes = []
        baseline_route_count = 0
        baseline_prefix_count = 0
        baseline_peer_count = 0
    has_sufficient = bool(baseline_exists and current_summary)
    return {
        "asn": normalized_asn,
        "target": target,
        "baseline_exists": baseline_exists,
        "baseline_status": baseline_status,
        "baseline_started_at": target.get("baseline_started_at"),
        "baseline_last_checked_at": target.get("baseline_last_checked_at"),
        "has_sufficient_baseline": has_sufficient,
        "latest_snapshot": latest_snapshot,
        "baseline_route_count": baseline_route_count,
        "baseline_prefix_count": baseline_prefix_count,
        "baseline_peer_count": baseline_peer_count,
        "baseline_sample_prefixes": snapshot_prefixes,
        "current_route_count": current_route_count,
        "current_prefix_count": current_prefix_count,
        "current_peer_count": current_peer_count,
        "current_summary": current_summary,
        "current": current,
        "snapshots_count": len(snapshots),
    }


def build_asn_route_change_answer(asn: int | str, question: str, request_uid: str | None = None) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    status = get_asn_baseline_summary(normalized_asn)
    current = status.get("current") or {}
    target = status.get("target") or {}
    current_snapshot = build_current_asn_snapshot(normalized_asn)
    latest_snapshot = status.get("latest_snapshot")
    current_summary = current.get("summary") or current_snapshot.get("summary") or {}
    recent_changes = current.get("recent_changes") or []

    if not status["baseline_exists"]:
        return {
            "asn": normalized_asn,
            "question": question,
            "request_uid": request_uid,
            "baseline_exists": False,
            "baseline_status": target.get("baseline_status") or "missing",
            "can_answer_historical_change": False,
            "route_change_analysis_status": "missing_baseline",
            "operational_answer": (
                f"Eu ainda não consigo afirmar se houve mudança de roteamento para o ASN {normalized_asn}, "
                "porque não tenho uma linha de base histórica suficiente desse ASN em monitoramento. "
                f"Posso adicionar o ASN {normalized_asn} ao monitoramento agora; a partir das próximas coletas, "
                "consigo detectar alterações de prefixos, peers e caminhos. Sou esperto, mas ainda não tenho bola mágica, meu querido operador."
            ),
            "what_i_know": {
                "current_route_count": int(current_summary.get("total_current_routes") or 0),
                "current_prefix_count": int(current_summary.get("total_prefixes") or 0),
                "current_peer_count": int(current_summary.get("total_peers") or 0),
                "recent_changes_count": len(recent_changes),
            },
            "what_i_dont_know": {
                "historical_comparison": "missing_baseline",
                "past_change_detection": "unavailable_without_monitoring_history",
            },
            "what_i_can_monitor": {
                "asn": normalized_asn,
                "label": target.get("label"),
                "status": target.get("status") or "not_monitored",
            },
            "current_routes": current.get("current_routes") or [],
            "recommended_actions": [
                {
                    "id": "add_asn_to_monitoring",
                    "label": "Adicionar ASN ao monitoramento",
                    "description": "Criar linha de base a partir de agora para detectar mudanças futuras.",
                    "requires_confirmation": True,
                    "risk": "state_change_monitoring",
                    "enabled": True,
                },
                {
                    "id": "generate_current_asn_snapshot",
                    "label": "Gerar snapshot atual do ASN",
                    "description": "Registrar visão atual de rotas/prefixos/peers como baseline inicial.",
                    "requires_confirmation": True,
                    "risk": "state_change_baseline",
                    "enabled": True,
                },
                {
                    "id": "show_current_asn_routes",
                    "label": "Ver rotas atuais do ASN",
                    "description": "Consultar rotas, prefixos e peers atuais sem alterar estado.",
                    "requires_confirmation": False,
                    "risk": "read_only",
                    "enabled": True,
                },
                {
                    "id": "create_asn_route_report",
                    "label": "Gerar relatório do ASN",
                    "description": "Consolidar estado atual, lacunas e monitoramento em um relatório.",
                    "requires_confirmation": False,
                    "risk": "read_only_report",
                    "enabled": True,
                },
            ],
            "monitoring_status": status,
        }

    comparison = compare_asn_snapshots(latest_snapshot or {}, current_snapshot)
    baseline_route_count = int(comparison.get("baseline_route_count") or status.get("baseline_route_count") or 0)
    current_route_count = int(comparison.get("current_route_count") or current_snapshot.get("route_count") or 0)
    route_delta = int(comparison.get("route_count_delta") or (current_route_count - baseline_route_count))
    current_prefix_count = int(comparison.get("current_prefix_count") or current_snapshot.get("prefix_count") or 0)
    route_change_detected = bool(comparison.get("change_detected"))
    prefixes_changed = sorted((comparison.get("added_prefixes") or []) + (comparison.get("removed_prefixes") or []))[:10]
    peers_changed = (comparison.get("peer_route_count_changes") or [])[:10]
    confidence = str(comparison.get("confidence") or "low")
    as_path_changes = comparison.get("as_path_changes") or []
    operational_answer = (
        f"Detectei mudança no roteamento observado para o ASN {normalized_asn} desde o snapshot de baseline. "
        if route_change_detected else
        f"Não encontrei mudança relevante entre a baseline e o estado atual para o ASN {normalized_asn}. "
    )
    operational_answer += (
        f"Rotas {route_delta:+d}, prefixos {int(comparison.get('prefix_count_delta') or 0):+d} e peers {int(comparison.get('peer_count_delta') or 0):+d}. "
    )
    if comparison.get("added_prefixes") or comparison.get("removed_prefixes"):
        operational_answer += (
            "Os prefixos mais relevantes foram "
            + ", ".join((comparison.get("added_prefixes") or [])[:5] + (comparison.get("removed_prefixes") or [])[:5])
            + ". "
        )
    if peers_changed:
        top_peer_changes = []
        for item in peers_changed[:5]:
            peer_ip = str(item.get("peer_ip") or "").strip()
            delta = int(item.get("route_count_delta") or 0)
            top_peer_changes.append(f"{peer_ip} ({delta:+d})")
        if top_peer_changes:
            operational_answer += "Maiores movimentos por peer: " + ", ".join(top_peer_changes) + ". "
    if as_path_changes:
        operational_answer += f"Foram detectadas {len(as_path_changes)} alteração(ões) de AS path no recorte comparado. "
    operational_answer += "Posso detalhar o relatório operacional ou manter esse ASN sob monitoramento contínuo."
    if not route_change_detected:
        operational_answer = (
            f"Não encontrei mudança relevante entre a baseline e o estado atual para o ASN {normalized_asn}. "
            f"Route count, prefix count e peers permanecem dentro da mesma visão observada. "
            f"Isto vale para a cobertura do RouteBrain; se a baseline for parcial, a conclusão também é parcial."
        )
    return {
        "asn": normalized_asn,
        "question": question,
        "request_uid": request_uid,
        "baseline_exists": True,
        "baseline_status": target.get("baseline_status") or "started",
        "can_answer_historical_change": True,
        "route_change_analysis_status": "detailed_comparison",
        "operational_answer": operational_answer,
        "what_i_know": {
            "current_route_count": current_route_count,
            "current_prefix_count": current_prefix_count,
            "current_peer_count": int(status.get("current_peer_count") or 0),
            "route_delta": route_delta,
            "confidence": confidence,
            "snapshot_count": status.get("snapshots_count") or 0,
            "peer_count_delta": int(comparison.get("peer_count_delta") or 0),
        },
        "what_i_dont_know": {
            "baseline_coverage": comparison.get("limitations") or [],
            "as_path_changes_supported": comparison.get("as_path_changes_supported"),
        },
        "what_i_can_monitor": {
            "asn": normalized_asn,
            "label": target.get("label"),
            "status": target.get("status") or "monitoring",
        },
        "current_routes": current.get("current_routes") or [],
        "recommended_actions": [
            {
                "id": "show_current_asn_routes",
                "label": "Ver rotas atuais do ASN",
                "description": "Consultar rotas, prefixos e peers atuais sem alterar estado.",
                "requires_confirmation": False,
                "risk": "read_only",
                "enabled": True,
            },
            {
                "id": "create_asn_route_report",
                "label": "Gerar relatório do ASN",
                "description": "Consolidar baseline, estado atual e diferenças observadas.",
                "requires_confirmation": False,
                "risk": "read_only_report",
                "enabled": True,
            },
            {
                "id": "generate_current_asn_snapshot",
                "label": "Gerar snapshot atual do ASN",
                "description": "Atualizar a baseline com uma nova visão do estado atual.",
                "requires_confirmation": True,
                "risk": "state_change_baseline",
                "enabled": True,
            },
        ],
        "monitoring_status": status,
        "analysis": {
            "route_change_detected": route_change_detected,
            "prefixes_changed": prefixes_changed,
            "peers_changed": peers_changed,
            "timestamp": latest_snapshot.get("snapshot_at") if latest_snapshot else None,
            "confidence": confidence,
            "gaps": comparison.get("limitations") or [],
        },
        "asn_route_change": {
            "asn": normalized_asn,
            "baseline_exists": True,
            "baseline_snapshot_at": comparison.get("baseline_snapshot_at"),
            "current_snapshot_at": comparison.get("current_snapshot_at"),
            "change_detected": route_change_detected,
            "confidence": confidence,
            "summary": {
                "route_count_delta": comparison.get("route_count_delta"),
                "prefix_count_delta": comparison.get("prefix_count_delta"),
                "peer_count_delta": comparison.get("peer_count_delta"),
            },
            "top_changes": {
                "added_prefixes": comparison.get("added_prefixes") or [],
                "removed_prefixes": comparison.get("removed_prefixes") or [],
                "changed_prefix_peers": comparison.get("changed_prefix_peers") or [],
                "peer_route_count_changes": comparison.get("peer_route_count_changes") or [],
                "as_path_changes": comparison.get("as_path_changes") or [],
            },
            "limitations": comparison.get("limitations") or [],
            "as_path_changes_supported": comparison.get("as_path_changes_supported"),
        },
    }
