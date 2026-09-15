from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from psycopg.rows import dict_row

from app.db.connection import get_connection


def _rows(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]


def _row(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    rows = _rows(sql, params)
    return rows[0] if rows else None


def _recent_run_uids(window_runs: int) -> list[str]:
    rows = _rows(
        """
        select run_uid
        from observed_destination_runs
        where run_uid is not null
        order by started_at desc, id desc
        limit %s
        """,
        (window_runs,),
    )
    return [row["run_uid"] for row in rows if row.get("run_uid")]


def _run_order(window_runs: int) -> list[dict[str, Any]]:
    return _rows(
        """
        select run_uid, started_at, finished_at, status, summary
        from observed_destination_runs
        where run_uid is not null
        order by started_at desc, id desc
        limit %s
        """,
        (window_runs,),
    )


def _series_by_destination(ip: str, window_runs: int) -> list[dict[str, Any]]:
    return _rows(
        """
        with recent_runs as (
            select run_uid, started_at, row_number() over (order by started_at desc, id desc) as run_rank
            from observed_destination_runs
            where run_uid is not null
            order by started_at desc, id desc
            limit %s
        )
        select
            r.run_uid,
            r.started_at as observed_at,
            sum(odi.observation_count)::bigint as count,
            array_remove(array_agg(distinct concat(coalesce(odi.destination_port::text, 'unknown'), '/', coalesce(odi.protocol, 'unknown')) order by concat(coalesce(odi.destination_port::text, 'unknown'), '/', coalesce(odi.protocol, 'unknown'))), null) as ports_protocols
        from recent_runs r
        left join observed_destination_run_items odi
               on odi.run_uid = r.run_uid
              and host(odi.destination_ip) = %s
        group by r.run_uid, r.started_at, r.run_rank
        order by r.started_at asc, r.run_rank asc
        """,
        (window_runs, ip),
    )


def _run_items_for_window(window_runs: int) -> list[dict[str, Any]]:
    return _rows(
        """
        with recent_runs as (
            select run_uid, started_at, row_number() over (order by started_at desc, id desc) as run_rank
            from observed_destination_runs
            where run_uid is not null
            order by started_at desc, id desc
            limit %s
        )
        select
            rr.run_uid,
            rr.started_at as observed_at,
            rr.run_rank,
            host(odi.destination_ip) as destination_ip,
            odi.destination_port,
            odi.protocol,
            odi.observation_count,
            odi.asn,
            odi.asn_source,
            odi.bgp_confirmed,
            odi.asn_confidence,
            odi.organization,
            odi.country,
            odi.category,
            odi.domain_guess,
            odi.enrichment_status
        from recent_runs rr
        left join observed_destination_run_items odi on odi.run_uid = rr.run_uid
        order by rr.started_at asc, rr.run_rank asc
        """,
        (window_runs,),
    )


def _window_rows_for_dimension(
    dimension_sql: str,
    window_runs: int,
) -> list[dict[str, Any]]:
    return _rows(
        f"""
        with recent_runs as (
            select run_uid, started_at, row_number() over (order by started_at desc, id desc) as run_rank
            from observed_destination_runs
            where run_uid is not null
            order by started_at desc, id desc
            limit %s
        )
        select {dimension_sql}, rr.run_uid, rr.started_at, coalesce(sum(odi.observation_count), 0)::bigint as count
        from recent_runs rr
        left join observed_destination_run_items odi on odi.run_uid = rr.run_uid
        group by {dimension_sql}, rr.run_uid, rr.started_at, rr.run_rank
        order by rr.started_at desc, rr.run_rank desc
        """,
        (window_runs,),
    )


def _trend_direction(current_count: float, previous_count: float, seen_runs_count: int) -> str:
    if seen_runs_count <= 0 and current_count > 0:
        return "new"
    if current_count <= 0 and previous_count > 0:
        return "disappeared"
    if current_count > previous_count:
        return "increasing"
    if current_count < previous_count:
        return "decreasing"
    return "stable"


def _build_trend_summary(series: list[dict[str, Any]]) -> dict[str, Any]:
    if not series:
        return {
            "trend_status": "insufficient_history",
            "current_count": 0,
            "previous_count": 0,
            "delta": 0,
            "delta_percent": 0,
            "trend_direction": "stable",
            "seen_runs_count": 0,
            "first_seen_run_uid": None,
            "last_seen_run_uid": None,
        }
    current = float(series[-1].get("count") or 0)
    previous = float(series[-2].get("count") or 0) if len(series) > 1 else 0.0
    seen_runs = sum(1 for row in series if (row.get("count") or 0) > 0)
    delta = current - previous
    delta_percent = 0.0 if previous == 0 else round((delta / previous) * 100, 2)
    return {
        "trend_status": "ok" if len(series) > 1 else "insufficient_history",
        "current_count": current,
        "previous_count": previous,
        "delta": delta,
        "delta_percent": delta_percent,
        "trend_direction": _trend_direction(current, previous, seen_runs),
        "seen_runs_count": seen_runs,
        "first_seen_run_uid": next((row.get("run_uid") for row in series if (row.get("count") or 0) > 0), None),
        "last_seen_run_uid": next((row.get("run_uid") for row in reversed(series) if (row.get("count") or 0) > 0), None),
    }


def get_observed_destination_trend(ip: str, window_runs: int = 10) -> dict[str, Any]:
    series = _series_by_destination(ip, window_runs)
    summary = _build_trend_summary(series)
    latest = _rows(
        """
        select host(destination_ip) as destination_ip, asn, organization, category, asn_source, bgp_confirmed, last_seen
        from observed_destinations
        where destination_ip = %s::inet
        order by observation_count desc, last_seen desc
        limit 1
        """,
        (ip,),
    )
    return {
        "destination_ip": ip,
        "runs": series,
        "summary": summary,
        "current": latest[0] if latest else None,
    }


def _dimension_trend(dimension_field: str, limit: int, window_runs: int) -> list[dict[str, Any]]:
    items = _run_items_for_window(window_runs)
    per_run: dict[str, dict[Any, int]] = defaultdict(lambda: defaultdict(int))
    run_meta: dict[str, dict[str, Any]] = {}
    for row in items:
        run_uid = row.get("run_uid")
        if not run_uid:
            continue
        run_meta[run_uid] = {"run_uid": run_uid, "observed_at": row.get("observed_at")}
        key = row.get(dimension_field)
        if key is None:
            continue
        per_run[run_uid][key] += int(row.get("observation_count") or 0)
    ordered_runs = sorted(run_meta.keys(), key=lambda uid: run_meta[uid]["observed_at"])
    totals: dict[Any, list[tuple[str, int]]] = defaultdict(list)
    for run_uid in ordered_runs:
        for key, count in per_run.get(run_uid, {}).items():
            totals[key].append((run_uid, count))
    results: list[dict[str, Any]] = []
    for key, series in totals.items():
        counts = [count for _, count in series]
        current = float(counts[-1]) if counts else 0.0
        previous = float(counts[-2]) if len(counts) > 1 else 0.0
        results.append(
            {
                "dimension_value": key,
                "last_seen_run_uid": series[-1][0] if series else None,
                "total_count": int(sum(counts)),
                "runs": [{"run_uid": run_uid, "count": count, "observed_at": run_meta[run_uid]["observed_at"]} for run_uid, count in series],
                "summary": {
                    "current_count": current,
                    "previous_count": previous,
                    "delta": current - previous,
                    "delta_percent": 0.0 if previous == 0 else round(((current - previous) / previous) * 100, 2),
                    "trend_direction": _trend_direction(current, previous, sum(1 for c in counts if c > 0)),
                },
            }
        )
    results.sort(key=lambda row: (row["summary"]["current_count"], row["total_count"], str(row["dimension_value"])), reverse=True)
    return results[:limit]


def get_top_destination_trends(limit: int = 50, window_runs: int = 10) -> list[dict[str, Any]]:
    items = _run_items_for_window(window_runs)
    run_meta: dict[str, dict[str, Any]] = {}
    per_destination: dict[str, dict[str, Any]] = defaultdict(lambda: {"runs": [], "asn": None, "organization": None, "category": None, "asn_source": None, "bgp_confirmed": None})
    for row in items:
        run_uid = row.get("run_uid")
        if not run_uid:
            continue
        run_meta[run_uid] = {"run_uid": run_uid, "observed_at": row.get("observed_at")}
        destination_ip = row.get("destination_ip")
        if not destination_ip:
            continue
        bucket = per_destination[destination_ip]
        count = int(row.get("observation_count") or 0)
        bucket["runs"].append((run_uid, count, row.get("observed_at"), row.get("destination_port"), row.get("protocol")))
        bucket["asn"] = row.get("asn")
        bucket["organization"] = row.get("organization")
        bucket["category"] = row.get("category")
        bucket["asn_source"] = row.get("asn_source")
        bucket["bgp_confirmed"] = row.get("bgp_confirmed")
    results: list[dict[str, Any]] = []
    for destination_ip, bucket in per_destination.items():
        series = bucket["runs"]
        series.sort(key=lambda item: item[2])
        counts = [count for _, count, _, _, _ in series]
        current = float(counts[-1]) if counts else 0.0
        previous = float(counts[-2]) if len(counts) > 1 else 0.0
        results.append(
            {
                "destination_ip": destination_ip,
                "asn": bucket["asn"],
                "organization": bucket["organization"],
                "category": bucket["category"],
                "asn_source": bucket["asn_source"],
                "bgp_confirmed": bucket["bgp_confirmed"],
                "current_count": current,
                "previous_count": previous,
                "delta": current - previous,
                "delta_percent": 0.0 if previous == 0 else round(((current - previous) / previous) * 100, 2),
                "trend_direction": _trend_direction(current, previous, sum(1 for c in counts if c > 0)),
                "last_seen": series[-1][2] if series else None,
                "seen_runs_count": sum(1 for c in counts if c > 0),
            }
        )
    results.sort(key=lambda row: (row["current_count"], row["delta"], row["destination_ip"]), reverse=True)
    return results[:limit]


def get_asn_trends(limit: int = 50, window_runs: int = 10) -> list[dict[str, Any]]:
    return _dimension_trend("asn", limit, window_runs)


def get_category_trends(limit: int = 50, window_runs: int = 10) -> list[dict[str, Any]]:
    return _dimension_trend("category", limit, window_runs)


def get_new_destinations(since_run_uid: str | None = None, window_runs: int = 5) -> list[dict[str, Any]]:
    items = _run_items_for_window(window_runs)
    per_destination: dict[str, list[tuple[str, Any, int]]] = defaultdict(list)
    for row in items:
        ip = row.get("destination_ip")
        if not ip:
            continue
        per_destination[ip].append((row.get("run_uid"), row.get("observed_at"), int(row.get("observation_count") or 0)))
    rows = []
    for ip, series in per_destination.items():
        series.sort(key=lambda item: item[1])
        if len(series) == 1 and series[0][2] > 0:
            rows.append({"destination_ip": ip, "first_seen_run_uid": series[0][0], "first_seen_at": series[0][1]})
    if since_run_uid:
        rows = [row for row in rows if row.get("first_seen_run_uid") == since_run_uid]
    return rows


def get_disappeared_destinations(window_runs: int = 5) -> list[dict[str, Any]]:
    items = _run_items_for_window(window_runs)
    per_destination: dict[str, list[int]] = defaultdict(list)
    per_meta: dict[str, list[tuple[str, Any]]] = defaultdict(list)
    for row in items:
        ip = row.get("destination_ip")
        if not ip:
            continue
        per_destination[ip].append(int(row.get("observation_count") or 0))
        per_meta[ip].append((row.get("run_uid"), row.get("observed_at")))
    rows = []
    for ip, counts in per_destination.items():
        if len(counts) > 1 and counts[-1] == 0 and any(c > 0 for c in counts[:-1]):
            run_uid, observed_at = per_meta[ip][-1]
            rows.append({"destination_ip": ip, "last_seen_run_uid": run_uid, "last_seen_at": observed_at})
    return rows


def summarize_observed_destination_trends(window_runs: int = 10) -> dict[str, Any]:
    runs = _run_order(window_runs)
    top_destinations = get_top_destination_trends(limit=5, window_runs=window_runs)
    top_asns = get_asn_trends(limit=5, window_runs=window_runs)
    top_categories = get_category_trends(limit=5, window_runs=window_runs)
    return {
        "total_runs": len(runs),
        "latest_run": runs[0] if runs else None,
        "trend_status": "insufficient_history" if len(runs) < 2 else "ok",
        "top_increasing": [row for row in top_destinations if row.get("trend_direction") == "increasing"][:5],
        "top_decreasing": [row for row in top_destinations if row.get("trend_direction") == "decreasing"][:5],
        "new_destinations": get_new_destinations(window_runs=window_runs),
        "disappeared_destinations": get_disappeared_destinations(window_runs=window_runs),
        "top_asn_changes": [row for row in top_asns if row.get("summary", {}).get("trend_direction") in {"increasing", "decreasing"}][:5],
        "top_category_changes": [row for row in top_categories if row.get("summary", {}).get("trend_direction") in {"increasing", "decreasing"}][:5],
    }
