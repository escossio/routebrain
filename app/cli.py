from __future__ import annotations

import argparse
import json
import ipaddress
import os
from pathlib import Path
from typing import Any

import requests
from requests import Response
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.services.route_graph_reporting import build_route_graph_report_for_run, render_route_graph_report_text

console = Console()
DEFAULT_API_TIMEOUT_SECONDS = 60


def _api_base_url() -> str:
    return os.getenv("ROUTEBRAIN_API_URL", "http://127.0.0.1:8000").rstrip("/")


def _api_auth() -> tuple[str, str] | None:
    username = os.getenv("ROUTEBRAIN_API_USERNAME", "").strip()
    password = os.getenv("ROUTEBRAIN_API_PASSWORD", "").strip()
    if username and password:
        return username, password
    return None


def _request(
    method: str,
    path: str,
    params: dict[str, Any] | None = None,
    json_data: Any | None = None,
    timeout: int = DEFAULT_API_TIMEOUT_SECONDS,
) -> Response:
    url = f"{_api_base_url()}{path}"
    try:
        return requests.request(method, url, params=params, json=json_data, auth=_api_auth(), timeout=timeout)
    except requests.RequestException as exc:
        error_detail = exc.__class__.__name__
        if str(exc):
            error_detail = f"{error_detail}: {exc}"
        console.print(
            f"[red]RouteBrain API não respondeu em {url} (timeout={timeout}s). "
            f"Erro: {error_detail}. Inicie com python3 scripts/run_api.py ou scripts/run_api_embed.sh[/red]"
        )
        raise SystemExit(1)


def _response_detail(response: Response) -> Any:
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip()
    if isinstance(payload, dict) and "detail" in payload:
        return payload["detail"]
    return payload


def _ensure_ok(response: Response) -> Any:
    if response.status_code >= 400:
        if response.status_code == 500:
            console.print("[red]RouteBrain API retornou erro interno. Tente novamente mais tarde.[/red]")
            raise SystemExit(1)

        detail = _response_detail(response)
        if isinstance(detail, (dict, list)):
            console.print_json(data=detail)
        else:
            console.print(f"[red]{detail}[/red]")
        raise SystemExit(1)
    return _response_detail(response)


def _print_table(rows: list[dict[str, Any]], columns: list[str], title: str) -> None:
    table = Table(title=title)
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(*[_format_cli_value(row.get(column, "")) for column in columns])
    console.print(table)


def _format_cli_value(value: Any, *, max_length: int = 240) -> str:
    if isinstance(value, (dict, list)):
        text = f"{type(value).__name__}({len(value)})"
    else:
        text = str(value)
    text = " ".join(text.split())
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 1]}…"


def _print_summary(data: dict[str, Any]) -> None:
    change_summary = data.get("change_summary", {}) or {}
    current_summary = data.get("current_summary", {}) or {}
    enrichment_summary = data.get("enrichment_summary", {}) or {}
    ping_summary = data.get("ping_enrichment_summary", {}) or {}
    traceroute_summary = data.get("traceroute_hop_summary", {}) or {}
    traceroute_classification_summary = data.get("traceroute_classification_summary", {}) or {}
    synthetic_summary = data.get("synthetic_summary", {}) or {}

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("field", style="bold")
    table.add_column("value")
    fields = [
        ("bgp_raw_routes", data.get("bgp_raw_routes")),
        ("bgp_current_routes", data.get("bgp_current_routes")),
        ("bgp_route_changes", data.get("bgp_route_changes")),
        ("total_changes", change_summary.get("total_changes")),
        ("total_prefixes_changed", change_summary.get("total_prefixes_changed")),
        ("total_current_routes", current_summary.get("total_current_routes")),
        ("matched_current_routes", enrichment_summary.get("matched_current_routes")),
        ("unmatched_current_routes", enrichment_summary.get("unmatched_current_routes")),
        ("matched_changes", enrichment_summary.get("matched_changes")),
        ("unmatched_changes", enrichment_summary.get("unmatched_changes")),
        ("active_ping_count", data.get("active_ping_count")),
        ("active_traceroute_measurement_count", data.get("active_traceroute_measurement_count")),
        ("active_traceroute_hop_count", data.get("active_traceroute_hop_count")),
        ("traceroute_summary_count_targets", data.get("traceroute_summary_count_targets")),
        ("total_hops", traceroute_summary.get("total_hops")),
        ("private_hops", traceroute_summary.get("private_hops")),
        ("matched_interface_hops", traceroute_summary.get("matched_interface_hops")),
        ("unmatched_hops", traceroute_summary.get("unmatched_hops")),
        ("classified_hops", traceroute_classification_summary.get("classified_hops")),
        ("private_classified_hops", traceroute_classification_summary.get("private_classified_hops")),
        ("private_unmatched_hops", traceroute_classification_summary.get("private_unmatched_hops")),
        ("distinct_classified_hop_ips", traceroute_classification_summary.get("distinct_classified_hop_ips")),
        ("peers_with_ping", ping_summary.get("peers_with_ping")),
        ("peers_without_ping", ping_summary.get("peers_without_ping")),
        ("avg_rtt_avg_ms", ping_summary.get("avg_rtt_avg_ms")),
        ("max_rtt_avg_ms", ping_summary.get("max_rtt_avg_ms")),
        ("synthetic_browser_runs_count", synthetic_summary.get("synthetic_browser_runs_count")),
        ("latest_synthetic_url", synthetic_summary.get("latest_synthetic_url")),
        ("latest_synthetic_total_ips_measured", synthetic_summary.get("latest_synthetic_total_ips_measured")),
        ("latest_synthetic_ping_success", synthetic_summary.get("latest_synthetic_ping_success")),
        ("latest_synthetic_avg_rtt_avg_ms", synthetic_summary.get("latest_synthetic_avg_rtt_avg_ms")),
        ("latest_synthetic_traceroute_success", synthetic_summary.get("latest_synthetic_traceroute_success")),
        ("latest_synthetic_ips_with_bgp_match", synthetic_summary.get("latest_synthetic_ips_with_bgp_match")),
    ]
    for field, value in fields:
        table.add_row(str(field), str(value))
    console.print(Panel(table, title="RouteBrain Summary", expand=False))


def cmd_health(_: argparse.Namespace) -> None:
    response = _request("GET", "/health")
    data = _ensure_ok(response)
    console.print(Panel.fit(f"{data['status']} - {data['service']}", title="Health"))


def cmd_summary(_: argparse.Namespace) -> None:
    response = _request("GET", "/summary")
    data = _ensure_ok(response)
    _print_summary(data)


def cmd_latest_changes(args: argparse.Namespace) -> None:
    response = _request("GET", "/changes/latest", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "detected_at",
            "prefix",
            "peer_ip",
            "peer_asn",
            "change_type",
            "inventory_peer_name",
            "inventory_connection_type",
            "ixp_name",
            "enrichment_status",
        ],
        "Latest BGP Changes",
    )


def _normalize_peer_cli_arg(peer: str) -> str:
    text = peer.strip()
    if "/" not in text:
        return text
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return text
    if network.prefixlen in {32, 128}:
        return str(network.network_address)
    console.print("[red]Peer precisa ser IP ou ASN; rede CIDR não é aceita aqui.[/red]")
    raise SystemExit(1)


def cmd_prefix(args: argparse.Namespace) -> None:
    response = _request("GET", "/bgp/prefix", params={"prefix": args.prefix, "limit": args.limit})
    data = _ensure_ok(response)
    query = data.get("query", {}) or {}
    console.print(Panel.fit(f"Prefix: {query.get('prefix')}", title="Prefix Lookup"))
    _print_summary_panel(
        "Prefix Summary",
        data.get("summary") or {},
        [
            "total_current_routes",
            "total_peers",
            "total_peer_asns",
            "total_origin_asns",
            "total_collectors",
            "first_seen_min",
            "last_seen_max",
        ],
    )
    _print_table(
        data.get("peer_counts", []),
        ["peer_ip", "peer_asn", "total_routes", "first_seen_min", "last_seen_max"],
        "Peers Announcing Prefix",
    )
    _print_table(
        data.get("current_routes", []),
        [
            "source",
            "collector",
            "peer_ip",
            "peer_asn",
            "as_path",
            "origin_asn",
            "origin_type",
            "inventory_peer_name",
            "enrichment_status",
            "ping_status",
            "rtt_avg_ms",
        ],
        "Current Routes",
    )
    _print_table(
        data.get("recent_changes", []),
        [
            "detected_at",
            "peer_ip",
            "peer_asn",
            "change_type",
            "old_as_path",
            "new_as_path",
            "old_origin_asn",
            "new_origin_asn",
            "inventory_peer_name",
            "enrichment_status",
            "ping_status",
            "rtt_avg_ms",
        ],
        "Recent Changes",
    )


def cmd_ip(args: argparse.Namespace) -> None:
    response = _request("GET", "/bgp/ip", params={"ip": args.ip})
    data = _ensure_ok(response)
    query = data.get("query", {}) or {}
    matched = bool(data.get("matched"))
    console.print(Panel.fit(f"IP: {query.get('ip')} ({'matched' if matched else 'no-match'})", title="IP Lookup"))
    _print_summary_panel(
        "IP Summary",
        {
            "matched": matched,
            "matched_prefix": data.get("matched_prefix"),
            "origin_asn": data.get("origin_asn"),
            "origin_type": data.get("origin_type"),
            "match_route_count": data.get("match_route_count"),
            "peer_count": data.get("peer_count"),
            "collector_count": data.get("collector_count"),
        },
        [
            "matched",
            "matched_prefix",
            "origin_asn",
            "origin_type",
            "match_route_count",
            "peer_count",
            "collector_count",
        ],
    )
    _print_table(
        data.get("current_routes", []),
        ["source", "collector", "peer_ip", "peer_asn", "prefix", "as_path", "origin_asn", "origin_type", "first_seen", "last_seen"],
        "Matching Routes",
    )
    _print_table(
        data.get("peer_counts", []),
        ["peer_ip", "peer_asn", "total_routes", "first_seen_min", "last_seen_max"],
        "Peers Announcing Matched Prefix",
    )


def cmd_asn(args: argparse.Namespace) -> None:
    response = _request("GET", f"/bgp/asn/{args.asn}", params={"limit": args.limit})
    data = _ensure_ok(response)
    query = data.get("query", {}) or {}
    console.print(Panel.fit(f"ASN: {query.get('asn')}", title="ASN Lookup"))
    summary = data.get("summary") or {}
    _print_summary_panel(
        "ASN Summary",
        {
            "route_count": summary.get("route_count", summary.get("total_current_routes")),
            "prefix_count": summary.get("prefix_count", summary.get("total_prefixes")),
            "peer_count": summary.get("peer_count", summary.get("total_peers")),
            "collector_count": summary.get("collector_count", summary.get("total_collectors")),
            "updated_at": summary.get("updated_at"),
        },
        [
            "route_count",
            "prefix_count",
            "peer_count",
            "collector_count",
            "updated_at",
        ],
    )
    _print_table(
        data.get("prefixes", []),
        ["prefix", "total_routes", "total_peers", "first_seen_min", "last_seen_max"],
        "Prefixes Originated by ASN",
    )
    _print_table(
        data.get("top_peers", []),
        ["peer_ip", "peer_asn", "total_routes", "total_prefixes", "first_seen_min", "last_seen_max"],
        "Top Peers Seeing ASN",
    )
    _print_table(
        data.get("current_routes", []),
        [
            "prefix",
            "peer_ip",
            "peer_asn",
            "as_path",
            "origin_type",
            "inventory_peer_name",
            "enrichment_status",
            "ping_status",
            "rtt_avg_ms",
        ],
        "Current Routes",
    )
    _print_table(
        data.get("recent_changes", []),
        [
            "detected_at",
            "prefix",
            "peer_ip",
            "peer_asn",
            "change_type",
            "old_as_path",
            "new_as_path",
            "old_origin_asn",
            "new_origin_asn",
            "inventory_peer_name",
            "enrichment_status",
            "ping_status",
            "rtt_avg_ms",
        ],
        "Recent Changes",
    )
    _print_table(data.get("change_distribution", []), ["change_type", "total_changes"], "ASN Change Distribution")


def cmd_peer(args: argparse.Namespace) -> None:
    peer_value = _normalize_peer_cli_arg(args.peer)
    response = _request("GET", f"/bgp/peer/{peer_value}", params={"limit": args.limit})
    data = _ensure_ok(response)
    query = data.get("query", {}) or {}
    mode = query.get("type")
    console.print(Panel.fit(f"Peer: {query.get('peer')} ({mode})", title="Peer Lookup"))
    summary = data.get("summary") or {}
    if mode == "peer_ip":
        _print_summary_panel(
            "Peer Summary",
            {
                "peer_ip": summary.get("peer_ip"),
                "peer_asn": summary.get("peer_asn"),
                "route_count": summary.get("route_count", summary.get("total_current_routes")),
                "prefix_count": summary.get("prefix_count", summary.get("total_prefixes")),
                "origin_asn_count": summary.get("origin_asn_count", summary.get("total_origin_asns")),
                "collector_count": summary.get("collector_count", summary.get("total_collectors")),
                "updated_at": summary.get("updated_at"),
            },
            [
                "peer_ip",
                "peer_asn",
                "route_count",
                "prefix_count",
                "origin_asn_count",
                "collector_count",
                "updated_at",
            ],
        )
    else:
        _print_summary_panel(
            "Peer ASN Summary",
            {
                "peer_asn": summary.get("peer_asn"),
                "route_count": summary.get("route_count", summary.get("total_current_routes")),
                "prefix_count": summary.get("prefix_count", summary.get("total_prefixes")),
                "peer_count": summary.get("peer_count", summary.get("total_peer_ips")),
                "collector_count": summary.get("collector_count", summary.get("total_collectors")),
                "updated_at": summary.get("updated_at"),
            },
            [
                "peer_asn",
                "route_count",
                "prefix_count",
                "peer_count",
                "collector_count",
                "updated_at",
            ],
        )
    _print_table(
        data.get("observations", []),
        [
            "observed_peer_ip",
            "observed_peer_asn",
            "observed_routes",
            "observed_prefixes",
            "match_status",
            "inventory_peer_name",
            "inventory_connection_type",
            "inventory_status",
            "router_hostname",
            "ixp_name",
            "ping_status",
            "rtt_avg_ms",
        ],
        "Peers",
    )
    ping_detail = data.get("ping_detail")
    if ping_detail:
        _print_table([ping_detail], list(ping_detail.keys()), "Latest Ping")
    _print_table(
        data.get("current_routes", []),
        [
            "source",
            "collector",
            "prefix",
            "peer_ip",
            "peer_asn",
            "as_path",
            "origin_asn",
            "origin_type",
            "inventory_peer_name",
            "enrichment_status",
            "ping_status",
            "rtt_avg_ms",
            "packet_loss_percent",
        ],
        "Current Routes",
    )
    _print_table(
        data.get("recent_changes", []),
        [
            "detected_at",
            "prefix",
            "peer_ip",
            "peer_asn",
            "change_type",
            "old_as_path",
            "new_as_path",
            "old_origin_asn",
            "new_origin_asn",
            "inventory_peer_name",
            "enrichment_status",
            "ping_status",
            "rtt_avg_ms",
            "packet_loss_percent",
        ],
        "Recent Changes",
    )
    _print_table(data.get("change_distribution", []), ["change_type", "total_changes"], "Change Distribution")
    if data.get("change_totals"):
        _print_summary_panel(
            "Peer Change Totals",
            data.get("change_totals") or {},
            ["total_changes", "total_prefixes_changed", "total_old_origin_asns", "total_new_origin_asns"],
        )


def cmd_top_changes(args: argparse.Namespace) -> None:
    response = _request(
        "GET",
        "/bgp/top/changes",
        params={"limit": args.limit, "change_type": args.change_type, "since_hours": args.since_hours},
    )
    data = _ensure_ok(response)
    console.print(Panel.fit(f"Filters: {data.get('filters')}", title="Top Changes"))
    _print_table(data.get("change_distribution", []), ["change_type", "total_changes"], "Change Distribution")
    _print_table(
        data.get("top_prefixes", []),
        ["prefix", "total_changes", "new_route_count", "as_path_changed_count", "origin_type_changed_count", "updated_at"],
        "Top Prefixes by Changes",
    )
    _print_table(
        data.get("top_origin_asns", []),
        ["origin_asn", "total_changes", "new_route_count", "as_path_changed_count", "origin_type_changed_count", "updated_at"],
        "Top Origin ASNs by Changes",
    )
    _print_table(
        data.get("top_peers", []),
        ["peer_ip", "peer_asn", "total_changes", "new_route_count", "as_path_changed_count", "origin_type_changed_count", "updated_at"],
        "Top Peers by Changes",
    )


def cmd_top_prefixes(args: argparse.Namespace) -> None:
    response = _request(
        "GET",
        "/bgp/top/prefixes",
        params={"limit": args.limit, "change_type": args.change_type, "since_hours": args.since_hours},
    )
    data = _ensure_ok(response)
    _print_summary_panel("Top Prefixes Filters", data.get("filters") or {}, ["change_type", "since_hours"])
    _print_table(
        data.get("items", []),
        ["prefix", "total_changes", "new_route_count", "as_path_changed_count", "origin_type_changed_count", "updated_at"],
        "Top Prefixes",
    )


def cmd_top_origin_asns(args: argparse.Namespace) -> None:
    response = _request(
        "GET",
        "/bgp/top/origin-asns",
        params={"limit": args.limit, "change_type": args.change_type, "since_hours": args.since_hours},
    )
    data = _ensure_ok(response)
    _print_summary_panel("Top Origin ASNs Filters", data.get("filters") or {}, ["change_type", "since_hours"])
    _print_table(
        data.get("items", []),
        ["origin_asn", "route_count", "prefix_count", "peer_count", "collector_count", "updated_at"],
        "Top Origin ASNs",
    )


def cmd_top_peers(args: argparse.Namespace) -> None:
    response = _request(
        "GET",
        "/bgp/top/peers",
        params={"limit": args.limit, "change_type": args.change_type, "since_hours": args.since_hours},
    )
    data = _ensure_ok(response)
    _print_summary_panel("Top Peers Filters", data.get("filters") or {}, ["change_type", "since_hours"])
    _print_table(
        data.get("items", []),
        ["peer_ip", "peer_asn", "route_count", "prefix_count", "origin_asn_count", "collector_count", "updated_at"],
        "Top Peers",
    )


def cmd_observed_collect(args: argparse.Namespace) -> None:
    response = _request(
        "POST",
        "/observed-destinations/collect",
        json_data={"limit": args.limit, "dry_run": args.dry_run},
        timeout=120,
    )
    data = _ensure_ok(response)
    console.print_json(data=data)


def cmd_observed_destinations(args: argparse.Namespace) -> None:
    response = _request("GET", "/observed-destinations/top", params={"limit": args.limit})
    data = _ensure_ok(response)
    _print_table(
        data.get("items", []),
        [
            "destination_ip",
            "destination_port",
            "protocol",
            "observation_count",
            "first_seen",
            "last_seen",
            "asn",
            "asn_source",
            "bgp_confirmed",
            "asn_confidence",
            "organization",
            "country",
            "domain_guess",
            "category",
            "enrichment_status",
        ],
        "Observed Destinations",
    )


def cmd_observed_asns(args: argparse.Namespace) -> None:
    response = _request("GET", "/observed-destinations/asns", params={"limit": args.limit})
    data = _ensure_ok(response)
    _print_table(
        data.get("items", []),
        [
            "asn",
            "asn_source",
            "organization",
            "country",
            "destination_count",
            "total_observations",
            "bgp_confirmed_count",
            "external_inferred_count",
            "categories",
            "top_destinations",
        ],
        "Observed ASNs",
    )


def cmd_observed_categories(args: argparse.Namespace) -> None:
    response = _request("GET", "/observed-destinations/categories", params={"limit": args.limit})
    data = _ensure_ok(response)
    _print_table(
        data.get("items", []),
        ["category", "destination_count", "total_observations", "top_asns", "top_destinations"],
        "Observed Categories",
    )


def cmd_observed_promote(args: argparse.Namespace) -> None:
    payload: dict[str, Any] = {"confirm": bool(args.confirm)}
    if args.notes:
        payload["notes"] = {"text": args.notes}
    response = _request("POST", f"/observed-destinations/{args.ip}/promote", json_data=payload)
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Observed Baseline Promotion - {args.ip}",
        data,
        ["status", "created", "existing", "baseline_uid", "destination_ip", "baseline_status"],
    )


def cmd_observed_baselines(args: argparse.Namespace) -> None:
    response = _request("GET", "/observed-destinations/baselines", params={"limit": args.limit, "status": args.status})
    data = _ensure_ok(response)
    _print_table(
        data.get("items", []),
        ["baseline_uid", "destination_ip", "asn", "organization", "category", "status", "observation_count", "promoted_at", "last_seen", "asn_source", "bgp_confirmed"],
        "Observed Destination Baselines",
    )


def cmd_observed_baseline(args: argparse.Namespace) -> None:
    response = _request("GET", f"/observed-destinations/baselines/{args.ip}")
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Observed Baseline - {args.ip}",
        data,
        [
            "baseline_uid",
            "destination_ip",
            "status",
            "source",
            "promoted_at",
            "asn",
            "asn_source",
            "bgp_confirmed",
            "asn_confidence",
            "organization",
            "country",
            "category",
            "observation_count",
            "last_seen",
        ],
    )


def cmd_observed_report(args: argparse.Namespace) -> None:
    response = _request("GET", f"/observed-destinations/{args.ip}/report")
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Observed Destination Report - {args.ip}",
        data,
        ["destination_ip", "operational_report", "gaps", "recommended_actions"],
    )
    console.print_json(data=data)


def cmd_observed_measure(args: argparse.Namespace) -> None:
    payload = {"confirm": bool(args.confirm), "ping": True, "traceroute": True}
    response = _request("POST", f"/observed-destinations/baselines/{args.ip}/measure", json_data=payload, timeout=180)
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Observed Baseline Measurement - {args.ip}",
        data,
        ["status", "measurement_uid", "baseline_uid", "destination_ip", "graph_available", "graph_url"],
    )
    console.print_json(data=data)


def cmd_observed_measurements(args: argparse.Namespace) -> None:
    response = _request("GET", f"/observed-destinations/baselines/{args.ip}/measurements", params={"limit": args.limit})
    data = _ensure_ok(response)
    _print_table(
        data.get("items", []),
        ["measurement_uid", "status", "measurement_type", "started_at", "finished_at", "graph_available", "traceroute_run_id"],
        "Observed Baseline Measurements",
    )


def cmd_observed_traceroute_graph(args: argparse.Namespace) -> None:
    response = _request("GET", f"/observed-destinations/baselines/{args.ip}/traceroute-graph")
    data = _ensure_ok(response)
    console.print_json(data=data)


def cmd_routegraph_report(args: argparse.Namespace) -> None:
    try:
        report = build_route_graph_report_for_run(args.run_uid)
    except ValueError as exc:
        console.print_json(data={"status": "error", "message": str(exc)})
        raise SystemExit(1)
    if args.format == "text":
        console.print(render_route_graph_report_text(report))
    else:
        console.print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str))


def cmd_observed_trends(args: argparse.Namespace) -> None:
    response = _request("GET", "/observed-destinations/trends", params={"limit": args.limit, "window_runs": args.window_runs})
    data = _ensure_ok(response)
    _print_table(
        data.get("items", []),
        ["destination_ip", "asn", "organization", "category", "current_count", "previous_count", "delta", "trend_direction", "last_seen"],
        "Observed Destination Trends",
    )


def cmd_observed_trend(args: argparse.Namespace) -> None:
    response = _request("GET", f"/observed-destinations/{args.ip}/trend", params={"window_runs": args.window_runs})
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Observed Trend - {args.ip}",
        data.get("summary") or {},
        ["trend_status", "current_count", "previous_count", "delta", "delta_percent", "trend_direction", "seen_runs_count"],
    )
    _print_table(data.get("runs", []), ["run_uid", "observed_at", "count", "ports_protocols"], "Trend Runs")


def cmd_observed_trends_asns(args: argparse.Namespace) -> None:
    response = _request("GET", "/observed-destinations/trends/asns", params={"limit": args.limit, "window_runs": args.window_runs})
    data = _ensure_ok(response)
    _print_table(
        data.get("items", []),
        ["dimension_value", "summary", "last_seen_run_uid", "total_count"],
        "Observed ASN Trends",
    )


def cmd_observed_trends_categories(args: argparse.Namespace) -> None:
    response = _request("GET", "/observed-destinations/trends/categories", params={"limit": args.limit, "window_runs": args.window_runs})
    data = _ensure_ok(response)
    _print_table(
        data.get("items", []),
        ["dimension_value", "summary", "last_seen_run_uid", "total_count"],
        "Observed Category Trends",
    )


def cmd_observed_trends_summary(args: argparse.Namespace) -> None:
    response = _request("GET", "/observed-destinations/trends-summary", params={"window_runs": args.window_runs})
    data = _ensure_ok(response)
    console.print_json(data=data)


def cmd_observed_pending(args: argparse.Namespace) -> None:
    response = _request("GET", "/observed-destinations/enrichment-pending", params={"limit": args.limit})
    data = _ensure_ok(response)
    _print_table(
        data.get("items", []),
        ["destination_ip", "destination_port", "protocol", "enrichment_status", "last_seen"],
        "Observed Pending Enrichment",
    )


def cmd_observed_enrich(args: argparse.Namespace) -> None:
    response = _request(
        "POST",
        "/observed-destinations/enrich",
        json_data={
            "limit": args.limit,
            "refresh": args.refresh,
            "resolve_bgp": args.resolve_bgp,
            "allow_external_asn": args.allow_external_asn,
        },
        timeout=120,
    )
    data = _ensure_ok(response)
    console.print_json(data=data)


def cmd_questions(_: argparse.Namespace) -> None:
    docs_path = Path(__file__).resolve().parents[1] / "docs" / "ROUTEBRAIN_QUESTIONS.md"
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"Docs: {docs_path}",
                    "",
                    "Perguntas já respondíveis hoje:",
                    "- prefixo existe e quem anuncia",
                    "- ASN origem e seus prefixos",
                    "- peer summary com inventário e ping",
                    "- top changes por prefixo, ASN e peer",
                    "- hosts, sites, peer links e peers sem inventário",
                    "- contexto público IX.br/CE para orientar inventário",
                ]
            ),
            title="RouteBrain Questions",
        )
    )


def cmd_unmatched_peers(args: argparse.Namespace) -> None:
    cmd_inventory_peers_unmatched(args)


def cmd_matched_peers(args: argparse.Namespace) -> None:
    response = _request("GET", "/inventory/peers/matched", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "observed_peer_ip",
            "observed_peer_asn",
            "observed_routes",
            "observed_prefixes",
            "inventory_peer_name",
            "inventory_connection_type",
            "ixp_name",
            "router_hostname",
            "match_status",
        ],
        "Matched Peers",
    )


def cmd_inventory_sites(_: argparse.Namespace) -> None:
    response = _request("GET", "/inventory/sites")
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "site_code",
            "name",
            "site_type",
            "city",
            "state",
            "country",
            "facility",
            "host_count",
            "peer_link_count",
            "updated_at",
        ],
        "Inventory Sites",
    )


def cmd_inventory_site(args: argparse.Namespace) -> None:
    response = _request("GET", f"/inventory/sites/{args.site_code}")
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Site {data.get('site_code')}",
        data,
        [
            "site_code",
            "name",
            "site_type",
            "city",
            "state",
            "country",
            "facility",
            "host_count",
            "interface_count",
            "peer_link_count",
            "updated_at",
        ],
    )


def cmd_inventory_hosts(args: argparse.Namespace) -> None:
    params = {"limit": args.limit}
    if args.site_code:
        params["site_code"] = args.site_code
    if args.role:
        params["role"] = args.role
    if args.tag:
        params["tag"] = args.tag
    response = _request("GET", "/inventory/hosts", params=params)
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "hostname",
            "site_code",
            "site_name",
            "role",
            "mgmt_ip",
            "status",
            "interface_count",
            "peer_link_count",
            "tag_count",
            "updated_at",
        ],
        "Inventory Hosts",
    )


def cmd_inventory_host(args: argparse.Namespace) -> None:
    response = _request("GET", f"/inventory/hosts/{args.hostname}")
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Host {data.get('hostname')}",
        data,
        [
            "hostname",
            "site_code",
            "site_name",
            "role",
            "mgmt_ip",
            "status",
            "interface_count",
            "peer_link_count",
            "tag_count",
            "updated_at",
        ],
    )
    _print_table(data.get("tags", []), ["tag", "description"], "Host Tags")
    _print_table(
        data.get("interfaces", []),
        ["interface_name", "interface_ip", "description", "peer_ip", "peer_asn", "status", "updated_at"],
        "Host Interfaces",
    )
    _print_table(
        data.get("peer_links", []),
        ["peer_ip", "peer_asn", "relation_type", "confidence", "source", "interface_name", "site_code", "updated_at"],
        "Peer Links",
    )
    _print_table(
        data.get("observations", []),
        ["observation_type", "observation", "source", "created_at"],
        "Host Observations",
    )


def cmd_inventory_search(args: argparse.Namespace) -> None:
    response = _request("GET", "/inventory/search", params={"q": args.query, "limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "hostname",
            "site_code",
            "site_name",
            "role",
            "mgmt_ip",
            "status",
            "interface_count",
            "peer_link_count",
            "tag_count",
            "updated_at",
        ],
        "Inventory Search",
    )


def cmd_inventory_peers_unmatched(args: argparse.Namespace) -> None:
    response = _request("GET", "/inventory/peers/unmatched", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        ["peer_ip", "peer_asn", "observed_routes", "observed_prefixes", "collector_count", "match_status"],
        "Inventory Peers Unmatched",
    )


def cmd_inventory_peer_links(args: argparse.Namespace) -> None:
    params: dict[str, Any] = {"limit": args.limit}
    if args.site_code:
        params["site_code"] = args.site_code
    if args.peer_ip:
        params["peer_ip"] = args.peer_ip
    if args.peer_asn is not None:
        params["peer_asn"] = args.peer_asn
    response = _request("GET", "/inventory/peer-links", params=params)
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "peer_ip",
            "peer_asn",
            "hostname",
            "site_code",
            "site_name",
            "interface_name",
            "interface_ip",
            "relation_type",
            "confidence",
            "source",
            "updated_at",
        ],
        "Inventory Peer Links",
    )


def cmd_inventory_discover(args: argparse.Namespace) -> None:
    payload = {
        "source": args.source,
        "dry_run": bool(args.dry_run),
        "limit": args.limit,
    }
    response = _request("POST", "/inventory/discovery/collect", json_data=payload, timeout=120)
    data = _ensure_ok(response)
    _print_summary_panel(
        "Inventory Discovery",
        data.get("counters", data),
        ["raw_seen", "candidates_seen", "inserted", "updated", "skipped"],
    )
    preview = data.get("preview") or []
    if preview:
        _print_table(
            preview[:20],
            ["ip", "mac", "hostname", "interface_name", "source_detail", "confidence", "status"],
            "Discovery Preview",
        )


def cmd_inventory_candidates(args: argparse.Namespace) -> None:
    params: dict[str, Any] = {"limit": args.limit}
    if args.status:
        params["status"] = args.status
    response = _request("GET", "/inventory/discovery/candidates", params=params)
    data = _ensure_ok(response)
    _print_summary_panel(
        "Inventory Discovery Summary",
        data.get("summary") or {},
        ["confirmed_hosts", "candidates", "high_confidence_candidates", "candidates_without_hostname", "last_discovery_at"],
    )
    _print_table(
        data.get("items", []),
        ["candidate_uid", "ip", "mac", "hostname", "interface_name", "source", "confidence", "status", "last_seen_at"],
        "Inventory Host Candidates",
    )


def cmd_inventory_candidate(args: argparse.Namespace) -> None:
    response = _request("GET", f"/inventory/discovery/candidates/{args.candidate_uid}")
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Candidate {data.get('candidate_uid')}",
        data,
        [
            "candidate_uid",
            "ip",
            "mac",
            "hostname",
            "interface_name",
            "site_code",
            "source",
            "source_detail",
            "confidence",
            "status",
            "promoted_host_id",
        ],
    )
    _print_table(
        data.get("evidence", []),
        ["evidence_type", "ip", "mac", "hostname", "interface_name", "observed_at"],
        "Candidate Evidence",
    )


def cmd_inventory_promote_candidate(args: argparse.Namespace) -> None:
    payload = {"confirm": bool(args.confirm), "site_code": args.site_code}
    response = _request("POST", f"/inventory/discovery/candidates/{args.candidate_uid}/promote", json_data=payload)
    data = _ensure_ok(response)
    console.print_json(data=data)


def cmd_inventory_ignore_candidate(args: argparse.Namespace) -> None:
    payload = {"confirm": bool(args.confirm), "reason": args.reason}
    response = _request("POST", f"/inventory/discovery/candidates/{args.candidate_uid}/ignore", json_data=payload)
    data = _ensure_ok(response)
    console.print_json(data=data)


def cmd_ixbr_locations(_: argparse.Namespace) -> None:
    response = _request("GET", "/ixbr/locations")
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "locality_code",
            "name",
            "city",
            "state",
            "participants_count",
            "route_server_observations_count",
            "discovery_runs_count",
            "fetched_at",
            "updated_at",
        ],
        "IX.br Locations",
    )


def cmd_ixbr_participants(args: argparse.Namespace) -> None:
    response = _request("GET", f"/ixbr/locations/{args.locality_code}/participants", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "asn",
            "participant_name",
            "participation_type",
            "atm_v4",
            "atm_v6",
            "transport_l2",
            "cix",
            "route_count",
            "prefix_count",
            "peer_count",
            "seen_as_origin",
            "fetched_at",
        ],
        f"IX.br Participants - {args.locality_code}",
    )


def cmd_ixbr_bgp_summary(args: argparse.Namespace) -> None:
    response = _request("GET", f"/ixbr/locations/{args.locality_code}/bgp-summary")
    data = _ensure_ok(response)
    _print_summary_panel(
        f"IX.br BGP Summary - {args.locality_code}",
        data,
        [
            "locality_code",
            "total_participants",
            "participants_seen_as_origin",
            "participants_not_seen_as_origin",
            "participants_fetched_at",
            "bgp_summary_updated_at",
        ],
    )
    _print_table(
        data.get("top_participants_by_current_routes", []),
        [
            "asn",
            "participant_name",
            "participation_type",
            "route_count",
            "prefix_count",
            "peer_count",
            "collector_count",
            "bgp_updated_at",
        ],
        f"IX.br Top Participants by Current Routes - {args.locality_code}",
    )
    _print_table(
        data.get("top_participants_by_changes", []),
        [
            "asn",
            "participant_name",
            "participation_type",
            "total_changes",
            "new_route_count",
            "as_path_changed_count",
            "origin_type_changed_count",
            "bgp_changes_updated_at",
        ],
        f"IX.br Top Participants by Changes - {args.locality_code}",
    )


def cmd_ixbr_seen_as_origin(args: argparse.Namespace) -> None:
    response = _request("GET", f"/ixbr/locations/{args.locality_code}/participants/seen-as-origin", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "asn",
            "participant_name",
            "participation_type",
            "route_count",
            "prefix_count",
            "peer_count",
            "collector_count",
            "bgp_updated_at",
        ],
        f"IX.br Participants Seen as Origin - {args.locality_code}",
    )


def cmd_ixbr_not_seen_as_origin(args: argparse.Namespace) -> None:
    response = _request(
        "GET",
        f"/ixbr/locations/{args.locality_code}/participants/not-seen-as-origin",
        params={"limit": args.limit},
    )
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "asn",
            "participant_name",
            "participation_type",
            "atm_v4",
            "atm_v6",
            "transport_l2",
            "cix",
            "fetched_at",
        ],
        f"IX.br Participants Not Seen as Origin - {args.locality_code}",
    )


def _print_learning_request_bundle(data: dict[str, Any], title: str) -> None:
    request = data.get("request") or {}
    analysis = data.get("analysis") or {}
    execution = data.get("execution") or {}
    answer = data.get("answer") or {}
    semantic_context = data.get("semantic_context") or (request.get("raw_context") or {}).get("semantic_context")
    if not semantic_context and answer:
        semantic_context = answer.get("semantic_context")

    _print_summary_panel(
        title,
        request,
        [
            "request_uid",
            "question",
            "normalized_question",
            "intent",
            "scope",
            "status",
            "operator",
            "requires_consent",
            "consent_status",
            "confidence_before",
            "confidence_after",
            "answer_summary",
            "created_at",
            "updated_at",
            "started_at",
            "finished_at",
            "error",
        ],
    )
    _print_table(
        data.get("entities", []),
        ["entity_type", "entity_value", "normalized_value", "confidence", "source", "created_at"],
        f"{title} - Entities",
    )
    _print_table(
        data.get("gaps", []),
        ["gap_type", "description", "severity", "blocks_answer", "recommended_task_type", "status"],
        f"{title} - Gaps",
    )
    _print_table(
        data.get("tasks", []),
        ["task_uid", "task_type", "status", "priority", "requires_consent", "command_preview", "error"],
        f"{title} - Tasks",
    )
    _print_table(
        data.get("evidence", []),
        ["evidence_type", "entity_type", "entity_value", "confidence", "source", "summary", "created_at"],
        f"{title} - Evidence",
    )
    if analysis:
        analysis_summary = {
            "known_count": len(analysis.get("known") or []),
            "unknown_count": len(analysis.get("unknown") or []),
            "gap_count": len(analysis.get("gaps") or []),
            "planned_task_count": len(analysis.get("planned_tasks") or []),
        }
        _print_summary_panel(
            f"{title} - Analysis",
            analysis_summary,
            ["known_count", "unknown_count", "gap_count", "planned_task_count"],
        )
    if semantic_context:
        _print_semantic_context(semantic_context, f"{title} - Semantic Context")
    if execution:
        _print_summary_panel(f"{title} - Execution", execution, ["task_results"])
    if answer:
        _print_summary_panel(
            f"{title} - Answer",
            answer,
            ["answer_summary", "next_actions", "status", "intent", "scope", "learning_memory", "classifications"],
        )
        if answer.get("learning_memory"):
            _print_learning_memory(answer["learning_memory"], f"{title} - Learned Memory")
        if answer.get("classifications"):
            _print_learning_classifications(answer["classifications"], f"{title} - Operational Classification")


def _print_semantic_context(context: dict[str, Any], title: str = "Semantic Context") -> None:
    if not isinstance(context, dict):
        return
    top_results = context.get("results") or []
    _print_summary_panel(
        title,
        {
            "search_mode": context.get("search_mode"),
            "query": context.get("query"),
            "top_result": (
                f"{top_results[0].get('object_type')} {top_results[0].get('object_ref')}"
                if top_results and isinstance(top_results[0], dict)
                else None
            ),
            "error": context.get("error"),
        },
        ["search_mode", "query", "top_result", "error"],
    )
    _print_table(
        [row for row in top_results[:5] if isinstance(row, dict)],
        ["object_type", "object_ref", "title", "confidence", "family_key", "related_count", "search_mode", "reason", "snippet"],
        f"{title} - Results",
    )


def _print_learning_memory(memory: dict[str, Any], title: str = "Learning Memory") -> None:
    if not isinstance(memory, dict):
        return
    entity_type = memory.get("entity_type")
    entity_value = memory.get("entity_value")
    summary_text = memory.get("summary_text")
    payload = memory.get("memory") or memory
    status = (
        memory.get("status")
        or (payload.get("dns", {}).get("freshness") or {}).get("status")
        or (payload.get("freshness") or {}).get("status")
    )
    _print_summary_panel(
        title,
        {
            "entity_type": entity_type,
            "entity_value": entity_value,
            "summary_text": summary_text,
            "status": status,
        },
        ["entity_type", "entity_value", "status", "summary_text"],
    )
    dns = payload.get("dns") or {}
    _print_summary_panel(
        f"{title} - DNS",
        {
            "status": (dns.get("freshness") or {}).get("status"),
            "age_human": (dns.get("freshness") or {}).get("age_human"),
            "expires_at": (dns.get("freshness") or {}).get("expires_at"),
            "resolved_ips": ", ".join(dns.get("resolved_ips") or []),
            "request_uid": dns.get("request_uid"),
        },
        ["status", "age_human", "expires_at", "resolved_ips", "request_uid"],
    )
    ips = payload.get("ips") or []
    table_rows: list[dict[str, Any]] = []
    for item in ips:
        bgp = item.get("bgp") or {}
        ping = item.get("ping") or {}
        traceroute = item.get("traceroute") or {}
        table_rows.append(
            {
                "ip": item.get("ip"),
                "bgp_status": bgp.get("status"),
                "bgp_age": bgp.get("age_human"),
                "ping_status": ping.get("status"),
                "ping_age": ping.get("age_human"),
                "traceroute_status": traceroute.get("status"),
                "traceroute_age": traceroute.get("age_human"),
            }
        )
    if table_rows:
        _print_table(
            table_rows,
            ["ip", "bgp_status", "bgp_age", "ping_status", "ping_age", "traceroute_status", "traceroute_age"],
            f"{title} - IP Memory",
        )
    related_requests = payload.get("related_requests") or []
    if related_requests:
        _print_table(
            related_requests,
            ["request_uid", "intent", "status", "question", "created_at"],
            f"{title} - Related Requests",
        )


def _print_learning_classifications(classifications: list[dict[str, Any]], title: str = "Operational Classification") -> None:
    if not classifications:
        return
    _print_table(
        classifications,
        [
            "entity_type",
            "entity_value",
            "classification_type",
            "classification_value",
            "confidence",
            "source",
            "reason",
            "created_at",
        ],
        title,
    )


def _print_external_enrichment(data: dict[str, Any], title: str) -> None:
    _print_summary_panel(
        title,
        data,
        ["entity_type", "entity_value", "status", "cache_hit", "summary_text", "freshness", "warnings"],
    )
    cache = data.get("cache") or {}
    cache_rows: list[dict[str, Any]] = []
    if isinstance(cache, dict):
        for source_name, row in cache.items():
            if isinstance(row, dict):
                cache_rows.append(
                    {
                        "source": source_name,
                        "cache_key": row.get("cache_key"),
                        "status": row.get("status"),
                        "freshness": (row.get("freshness") or {}).get("status"),
                        "age_human": (row.get("freshness") or {}).get("age_human"),
                        "error": row.get("error"),
                    }
                )
    if cache_rows:
        _print_table(cache_rows, ["source", "cache_key", "status", "freshness", "age_human", "error"], f"{title} - Cache")
    normalized = data.get("normalized")
    if isinstance(normalized, dict):
        _print_summary_panel(
            f"{title} - Normalized",
            normalized,
            [
                "asn",
                "ip",
                "organization_name",
                "country",
                "network_name",
                "website",
                "looking_glass",
                "route_server",
                "network_type",
                "info_type",
                "info_prefixes4",
                "info_prefixes6",
                "peering_policy",
                "source",
                "confidence",
                "fetched_at",
            ],
        )
    warnings = data.get("warnings") or []
    if warnings:
        _print_table([{"warning": warning} for warning in warnings], ["warning"], f"{title} - Warnings")


def cmd_learning_ask(args: argparse.Namespace) -> None:
    question = " ".join(args.question).strip()
    payload = {"question": question, "operator": args.operator, "dry_run": True}
    response = _request("POST", "/learning/requests", json_data=payload, timeout=180)
    data = _ensure_ok(response)
    request = data.get("request") or {}
    answer = data.get("answer") or {}
    semantic_context = data.get("semantic_context") or (request.get("raw_context") or {}).get("semantic_context")
    _print_summary_panel(
        "Learning Ask",
        {
            "request_uid": request.get("request_uid"),
            "intent": request.get("intent"),
            "status": request.get("status"),
            "answer_summary": request.get("answer_summary") or answer.get("answer_summary"),
        },
        ["request_uid", "intent", "status", "answer_summary"],
    )
    if semantic_context:
        _print_semantic_context(semantic_context, "Learning Ask - Semantic Context")
    _print_table(
        data.get("gaps", []),
        ["gap_type", "severity", "recommended_task_type", "status"],
        "Learning Ask - Gaps",
    )


def cmd_learning_request(args: argparse.Namespace) -> None:
    response = _request("GET", f"/learning/requests/{args.request_uid}")
    data = _ensure_ok(response)
    _print_learning_request_bundle(data, f"Learning Request {args.request_uid}")


def cmd_learning_approve(args: argparse.Namespace) -> None:
    response = _request("POST", f"/learning/requests/{args.request_uid}/approve")
    data = _ensure_ok(response)
    _print_learning_request_bundle(data, f"Learning Request {args.request_uid}")
    console.print(
        Panel.fit(
            f"Request aprovada. Para executar medições ativas, use: routebrain learn execute {args.request_uid} --active",
            title="Consentimento",
        )
    )


def cmd_learning_execute(args: argparse.Namespace) -> None:
    if args.active and not args.dry_run:
        request_response = _request("GET", f"/learning/requests/{args.request_uid}")
        request_data = _ensure_ok(request_response)
        consent_status = str((request_data.get("request") or {}).get("consent_status") or "").lower()
        if consent_status != "approved":
            console.print("[red]Medições ativas exigem approve antes.[/red]")
            raise SystemExit(1)
    response = _request(
        "POST",
        f"/learning/requests/{args.request_uid}/execute",
        json_data={
            "dry_run": args.dry_run,
            "allow_safe_tasks": True,
            "allow_active_measurements": bool(args.active and not args.dry_run),
            "force_refresh": bool(args.force_refresh),
        },
        timeout=300 if not args.dry_run else 30,
    )
    data = _ensure_ok(response)
    if args.dry_run:
        console.print(Panel.fit("Modo dry-run: nenhuma tarefa foi executada.", title="Learning Execute"))
        _print_summary_panel(
            f"Learning Execute Preview {args.request_uid}",
            data,
            ["dry_run", "request_uid", "note"],
        )
        _print_table(
            data.get("would_execute", []),
            ["task_uid", "task_type", "status", "priority", "requires_consent", "command_preview"],
            "Would Execute",
        )
        _print_table(
            data.get("would_wait_for_consent", []),
            ["task_uid", "task_type", "status", "priority", "requires_consent", "command_preview"],
            "Would Wait For Consent",
        )
        _print_table(
            data.get("active_measurement_plan", {}).get("selected_targets", []),
            ["ip", "version", "is_global", "is_private", "reason_if_blocked"],
            "Active Measurement Targets",
        )
        return
    refreshed = _request("GET", f"/learning/requests/{args.request_uid}")
    bundle = _ensure_ok(refreshed)
    _print_learning_request_bundle(bundle, f"Learning Request {args.request_uid}")


def cmd_learning_answer(args: argparse.Namespace) -> None:
    response = _request("GET", f"/learning/requests/{args.request_uid}/answer")
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Learning Answer {args.request_uid}",
        data,
        ["request_uid", "intent", "scope", "status", "answer_summary", "next_actions", "classifications"],
    )
    _print_table(data.get("known", []), ["kind", "entity_type", "entity_value", "confidence", "source", "summary"], "Known")
    _print_table(data.get("unknown", []), ["kind", "entity_type", "entity_value", "summary"], "Unknown")
    _print_table(data.get("gaps", []), ["gap_type", "description", "severity", "blocks_answer", "recommended_task_type"], "Gaps")
    _print_table(
        data.get("planned_tasks", []),
        ["task_uid", "task_type", "status", "priority", "requires_consent", "command_preview"],
        "Planned Tasks",
    )
    _print_table(
        data.get("evidence", []),
        ["evidence_type", "entity_type", "entity_value", "confidence", "source", "summary"],
        "Evidence",
    )
    if data.get("semantic_context"):
        _print_semantic_context(data["semantic_context"], "Answer Semantic Context")
    if data.get("learning_memory"):
        _print_learning_memory(data["learning_memory"], "Answer Memory")
    if data.get("classifications"):
        _print_learning_classifications(data["classifications"], "Operational Classification")


def cmd_learning_memory_domain(args: argparse.Namespace) -> None:
    response = _request("GET", f"/learning/memory/domain/{args.domain}")
    data = _ensure_ok(response)
    _print_learning_memory(data, f"Memory {args.domain}")


def cmd_learning_classify(args: argparse.Namespace) -> None:
    response = _request("POST", f"/learning/requests/{args.request_uid}/classify")
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Learning Classification {args.request_uid}",
        data,
        ["request_uid", "status", "summary_text"],
    )
    _print_learning_classifications(data.get("classifications", []), f"Classification {args.request_uid}")


def cmd_learning_classifications(args: argparse.Namespace) -> None:
    response = _request("GET", f"/learning/requests/{args.request_uid}/classifications")
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Learning Classifications {args.request_uid}",
        data,
        ["request_uid", "summary_text", "classifications"],
    )
    _print_learning_classifications(data.get("classifications", []), f"Classifications {args.request_uid}")


def cmd_learning_classify_domain(args: argparse.Namespace) -> None:
    response = _request("GET", "/learning/classifications/entity", params={"type": "domain", "value": args.domain})
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Learning Classification {args.domain}",
        data,
        ["entity_type", "entity_value", "status", "summary_text", "related_requests"],
    )
    _print_learning_classifications(data.get("classifications", []), f"Classification {args.domain}")


def cmd_learning_known_networks(_: argparse.Namespace) -> None:
    response = _request("GET", "/learning/known-networks")
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "match_type",
            "match_value",
            "classification_type",
            "classification_value",
            "confidence",
            "description",
            "source",
        ],
        "Known Networks",
    )


def _print_semantic_search_bundle(data: dict[str, Any], title: str) -> None:
    _print_summary_panel(
        title,
        data,
        ["query", "search_mode", "grouping", "object_type", "results_count"],
    )
    _print_table(
        data.get("results", []),
        [
            "document_uid",
            "object_type",
            "object_ref",
            "title",
            "score",
            "raw_vector_score",
            "text_score",
            "object_type_weight",
            "related_count",
            "family_key",
            "confidence",
            "search_mode",
            "reason",
            "snippet",
        ],
        f"{title} - Results",
    )


def _print_semantic_documents(rows: list[dict[str, Any]], title: str) -> None:
    _print_table(
        rows,
        [
            "document_uid",
            "object_type",
            "object_ref",
            "title",
            "confidence",
            "embedding_status",
            "updated_at",
        ],
        title,
    )


def _use_local_semantic_fallback() -> bool:
    local_provider = os.getenv("ROUTEBRAIN_EMBEDDING_PROVIDER", "").strip().lower()
    return local_provider in {"none", "text_fallback"} and not os.getenv("ROUTEBRAIN_API_URL")


def _print_semantic_health(data: dict[str, Any]) -> None:
    provider_info = data.get("provider_info") or {}
    pgvector = data.get("pgvector") or {}
    documents = data.get("documents") or {}
    search = data.get("search") or {}
    fallback = data.get("fallback") or {}
    flat = {
        "status": data.get("status"),
        "provider": data.get("provider") or provider_info.get("provider"),
        "model": data.get("model") or provider_info.get("model"),
        "provider_available": provider_info.get("is_available"),
        "provider_cached": provider_info.get("provider_cached"),
        "expected_dim": data.get("expected_dim"),
        "provider_dim": provider_info.get("dim"),
        "pgvector_installed": pgvector.get("installed"),
        "pgvector_version": pgvector.get("version"),
        "embedding_column_dim": pgvector.get("embedding_column_dim"),
        "semantic_documents": documents.get("semantic_documents"),
        "semantic_embeddings": documents.get("semantic_embeddings"),
        "embedded": documents.get("embedded"),
        "search_mode": search.get("search_mode"),
        "search_elapsed_seconds": search.get("elapsed_seconds"),
        "top_object_type": search.get("top_object_type"),
        "top_object_ref": search.get("top_object_ref"),
        "text_fallback_available": fallback.get("text_fallback_available"),
        "warnings_count": len(data.get("warnings") or []),
        "errors_count": len(data.get("errors") or []),
    }
    _print_summary_panel(
        "Semantic Health",
        flat,
        [
            "status",
            "provider",
            "model",
            "provider_available",
            "provider_cached",
            "expected_dim",
            "provider_dim",
            "pgvector_installed",
            "pgvector_version",
            "embedding_column_dim",
            "semantic_documents",
            "semantic_embeddings",
            "embedded",
            "search_mode",
            "search_elapsed_seconds",
            "top_object_type",
            "top_object_ref",
            "text_fallback_available",
            "warnings_count",
            "errors_count",
        ],
    )
    if data.get("warnings"):
        _print_table([{"warning": item} for item in data.get("warnings") or []], ["warning"], "Semantic Health - Warnings")
    if data.get("errors"):
        _print_table([{"error": item} for item in data.get("errors") or []], ["error"], "Semantic Health - Errors")


def cmd_semantic_rebuild(args: argparse.Namespace) -> None:
    response = _request(
        "POST",
        "/semantic/rebuild",
        json_data={
            "scope": args.scope,
            "dry_run": bool(args.dry_run),
            "limit": args.limit,
            "skip_existing": bool(args.skip_existing),
            "force": bool(args.force),
        },
        timeout=300,
    )
    data = _ensure_ok(response)
    _print_summary_panel(
        "Semantic Rebuild",
        data,
        [
            "scope",
            "limit",
            "dry_run",
            "skip_existing",
            "force",
            "status",
            "total_documents",
            "created",
            "updated",
            "unchanged",
            "search_mode",
            "provider",
        ],
    )
    _print_table(
        [{"object_type": key, "count": value} for key, value in sorted((data.get("by_object_type") or {}).items())],
        ["object_type", "count"],
        "Semantic Rebuild - Documents by Type",
    )
    _print_table(
        [{"embedding_status": key, "count": value} for key, value in sorted((data.get("embedding_status_counts") or {}).items())],
        ["embedding_status", "count"],
        "Semantic Rebuild - Embedding Status",
    )
    if data.get("errors"):
        _print_table(data.get("errors", []), ["status", "document_uid", "object_type", "object_ref", "title"], "Semantic Rebuild - Errors")


def cmd_semantic_search(args: argparse.Namespace) -> None:
    if _use_local_semantic_fallback():
        from app.services.semantic_memory import semantic_search

        data = semantic_search(args.query, limit=args.limit, object_type=args.object_type)
        _print_semantic_search_bundle(data, f"Semantic Search: {args.query}")
        return
    response = _request(
        "GET",
        "/semantic/search",
        params={"q": args.query, "limit": args.limit, "object_type": args.object_type},
        timeout=90,
    )
    data = _ensure_ok(response)
    _print_semantic_search_bundle(data, f"Semantic Search: {args.query}")


def cmd_semantic_health(_: argparse.Namespace) -> None:
    if _use_local_semantic_fallback():
        from app.services.semantic_memory import semantic_healthcheck

        _print_semantic_health(semantic_healthcheck())
        return
    response = _request("GET", "/semantic/health", timeout=45)
    data = _ensure_ok(response)
    _print_semantic_health(data)


def cmd_semantic_documents(args: argparse.Namespace) -> None:
    response = _request(
        "GET",
        "/semantic/documents",
        params={"limit": args.limit, "object_type": args.object_type},
    )
    rows = _ensure_ok(response)
    _print_semantic_documents(rows, "Semantic Documents")


def cmd_learning_search(args: argparse.Namespace) -> None:
    response = _request("GET", "/learning/search", params={"q": args.query, "limit": args.limit}, timeout=90)
    data = _ensure_ok(response)
    _print_semantic_search_bundle(data, f"Learning Search: {args.query}")


def cmd_enrich_asn(args: argparse.Namespace) -> None:
    response = _request("GET", f"/enrichment/asn/{args.asn}", params={"refresh": bool(args.refresh)})
    data = _ensure_ok(response)
    _print_external_enrichment(data, f"ASN Enrichment {args.asn}")


def cmd_enrich_ip(args: argparse.Namespace) -> None:
    response = _request("GET", "/enrichment/ip", params={"ip": args.ip, "refresh": bool(args.refresh)})
    data = _ensure_ok(response)
    _print_external_enrichment(data, f"IP Enrichment {args.ip}")


def cmd_learning_enrich(args: argparse.Namespace) -> None:
    response = _request(
        "POST",
        f"/learning/requests/{args.request_uid}/enrich",
        json_data={"force_refresh": bool(args.refresh), "allow_external": bool(args.allow_external)},
        timeout=300,
    )
    data = _ensure_ok(response)
    _print_summary_panel(
        f"Learning Enrich {args.request_uid}",
        data,
        ["request_uid", "status", "force_refresh", "allow_external", "summary_text", "warnings"],
    )
    if data.get("enrichment_results"):
        _print_table(
            data.get("enrichment_results", []),
            ["entity_type", "entity_value", "asn", "organization_name", "country", "network_name", "source", "confidence"],
            f"Learning Enrich {args.request_uid} - Results",
        )
    if data.get("classifications"):
        _print_learning_classifications(data.get("classifications", []), f"Learning Enrich {args.request_uid} - Classification")


def cmd_search_prefix(args: argparse.Namespace) -> None:
    response = _request("GET", "/search/prefix", params={"q": args.query, "limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "prefix",
            "peer_ip",
            "peer_asn",
            "as_path",
            "origin_asn",
            "inventory_peer_name",
            "inventory_connection_type",
            "ixp_name",
            "enrichment_status",
        ],
        "Prefix Search",
    )


def cmd_ping_latest(args: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/ping/latest", params={"limit": args.limit})
    rows = _ensure_ok(response)
    table_rows: list[dict[str, Any]] = []
    for row in rows:
        table_rows.append(
            {
                "target": row.get("target"),
                "label": row.get("target_label"),
                "status": row.get("status"),
                "sent/received": f"{row.get('packets_sent')}/{row.get('packets_received')}",
                "loss": row.get("packet_loss_percent"),
                "rtt_avg_ms": row.get("rtt_avg_ms"),
                "rtt_max_ms": row.get("rtt_max_ms"),
                "measured_at": row.get("measured_at"),
            }
        )
    _print_table(
        table_rows,
        ["target", "label", "status", "sent/received", "loss", "rtt_avg_ms", "rtt_max_ms", "measured_at"],
        "Latest Ping Measurements",
    )


def cmd_ping_summary(_: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/ping/summary")
    rows = _ensure_ok(response)
    table_rows: list[dict[str, Any]] = []
    for row in rows:
        table_rows.append(
            {
                "target": row.get("target"),
                "total_measurements": row.get("total_measurements"),
                "successful_measurements": row.get("successful_measurements"),
                "failed_measurements": row.get("failed_measurements"),
                "avg_loss": row.get("avg_packet_loss_percent"),
                "avg_rtt": row.get("avg_rtt_avg_ms"),
                "min_rtt": row.get("min_rtt_avg_ms"),
                "max_rtt": row.get("max_rtt_avg_ms"),
                "last_measured_at": row.get("last_measured_at"),
            }
        )
    _print_table(
        table_rows,
        [
            "target",
            "total_measurements",
            "successful_measurements",
            "failed_measurements",
            "avg_loss",
            "avg_rtt",
            "min_rtt",
            "max_rtt",
            "last_measured_at",
        ],
        "Ping Summary",
    )


def cmd_ping_history(args: argparse.Namespace) -> None:
    response = _request("GET", f"/measurements/ping/history/{args.target}", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "id",
            "target",
            "target_label",
            "source_label",
            "packets_sent",
            "packets_received",
            "packet_loss_percent",
            "rtt_min_ms",
            "rtt_avg_ms",
            "rtt_max_ms",
            "rtt_mdev_ms",
            "status",
            "measured_at",
        ],
        f"Ping History - {args.target}",
    )


def cmd_peers_ping(args: argparse.Namespace) -> None:
    response = _request("GET", "/peers/ping", params={"limit": args.limit})
    rows = _ensure_ok(response)
    table_rows: list[dict[str, Any]] = []
    for row in rows:
        table_rows.append(
            {
                "peer_ip": row.get("observed_peer_ip"),
                "asn": row.get("observed_peer_asn"),
                "routes": row.get("observed_routes"),
                "prefixes": row.get("observed_prefixes"),
                "peer_name": row.get("inventory_peer_name"),
                "ixp": row.get("ixp_name"),
                "match": row.get("match_status"),
                "ping_status": row.get("ping_status"),
                "loss": row.get("packet_loss_percent"),
                "rtt_avg_ms": row.get("rtt_avg_ms"),
            }
        )
    _print_table(
        table_rows,
        ["peer_ip", "asn", "routes", "prefixes", "peer_name", "ixp", "match", "ping_status", "loss", "rtt_avg_ms"],
        "Peers With Ping",
    )


def cmd_peers_missing_ping(args: argparse.Namespace) -> None:
    response = _request("GET", "/peers/ping/missing", params={"limit": args.limit})
    rows = _ensure_ok(response)
    table_rows: list[dict[str, Any]] = []
    for row in rows:
        table_rows.append(
            {
                "peer_ip": row.get("observed_peer_ip"),
                "asn": row.get("observed_peer_asn"),
                "routes": row.get("observed_routes"),
                "prefixes": row.get("observed_prefixes"),
                "match_status": row.get("match_status"),
                "inventory_peer_name": row.get("inventory_peer_name"),
            }
        )
    _print_table(
        table_rows,
        ["peer_ip", "asn", "routes", "prefixes", "match_status", "inventory_peer_name"],
        "Peers Missing Ping",
    )


def cmd_synthetic_latest(args: argparse.Namespace) -> None:
    response = _request("GET", "/synthetic/runs/latest", params={"limit": args.limit})
    rows = _ensure_ok(response)
    table_rows = [
        {
            "run_id": row.get("run_id"),
            "url": row.get("url"),
            "analyzed_at": row.get("analyzed_at"),
            "hosts": row.get("total_hosts"),
            "ips": row.get("total_ips_measured"),
            "ping_success": row.get("ping_success"),
            "avg_rtt": row.get("avg_rtt_avg_ms"),
            "traceroute_success": row.get("traceroute_success"),
            "bgp_matches": row.get("ips_with_bgp_match"),
        }
        for row in rows
    ]
    _print_table(
        table_rows,
        [
            "run_id",
            "url",
            "analyzed_at",
            "hosts",
            "ips",
            "ping_success",
            "avg_rtt",
            "traceroute_success",
            "bgp_matches",
        ],
        "Synthetic Latest Reports",
    )


def cmd_synthetic_run(args: argparse.Namespace) -> None:
    response = _request("GET", f"/synthetic/runs/{args.run_id}")
    data = _ensure_ok(response)
    summary = data.get("summary")
    if not summary:
        console.print("Run sintética não encontrada.")
        return
    _print_summary_panel(
        "Synthetic Run Summary",
        summary,
        [
            "run_id",
            "url",
            "final_url",
            "title",
            "label",
            "analyzed_at",
            "total_requests",
            "total_hosts",
            "total_ips_measured",
            "ping_success",
            "ping_failed",
            "avg_rtt_avg_ms",
            "min_rtt_avg_ms",
            "max_rtt_avg_ms",
            "traceroute_success",
            "traceroute_failed",
            "avg_traceroute_hop_count",
            "ips_with_bgp_match",
        ],
    )
    host_rows = [
        {
            "hostname": row.get("hostname"),
            "measured_ips": row.get("measured_ips"),
            "ping_success": row.get("ping_success"),
            "ping_failed": row.get("ping_failed"),
            "avg_rtt": row.get("avg_rtt_avg_ms"),
            "traceroute_success": row.get("traceroute_success"),
            "bgp_matches": row.get("ips_with_bgp_match"),
        }
        for row in data.get("hosts", [])
    ]
    _print_table(
        host_rows,
        ["hostname", "measured_ips", "ping_success", "ping_failed", "avg_rtt", "traceroute_success", "bgp_matches"],
        "Synthetic Run Hosts",
    )
    ip_rows = [
        {
            "hostname": row.get("hostname"),
            "ip": row.get("ip"),
            "bgp_route_count": row.get("bgp_route_count"),
            "ping_status": row.get("ping_status"),
            "loss": row.get("packet_loss_percent"),
            "rtt_avg": row.get("rtt_avg_ms"),
            "rtt_max": row.get("rtt_max_ms"),
            "traceroute_status": row.get("traceroute_status"),
            "hops": row.get("traceroute_hop_count"),
        }
        for row in data.get("ip_results", [])
    ]
    _print_table(
        ip_rows,
        ["hostname", "ip", "bgp_route_count", "ping_status", "loss", "rtt_avg", "rtt_max", "traceroute_status", "hops"],
        "Synthetic Run IP Results",
    )


def cmd_synthetic_domain(args: argparse.Namespace) -> None:
    response = _request("GET", "/synthetic/domain", params={"url": args.url})
    data = _ensure_ok(response)
    domain_summary = data.get("domain_summary")
    latest_run = data.get("latest_run")
    latest_ip_results = data.get("latest_ip_results") or []
    if not domain_summary and not latest_run:
        console.print("Domínio sintético não encontrado.")
        return

    if domain_summary:
        _print_summary_panel(
            "Synthetic Domain Summary",
            domain_summary,
            [
                "url",
                "final_url",
                "title",
                "total_runs",
                "last_run_id",
                "first_analyzed_at",
                "last_analyzed_at",
                "total_hosts_observed",
                "total_ips_measured",
                "total_ping_success",
                "total_ping_failed",
                "avg_rtt_avg_ms",
                "min_rtt_avg_ms",
                "max_rtt_avg_ms",
                "total_traceroutes_run",
                "total_traceroute_success",
                "avg_traceroute_hops",
                "total_ips_with_bgp_match",
            ],
        )
    if latest_run:
        _print_summary_panel(
            "Latest Synthetic Run",
            latest_run,
            [
                "run_id",
                "url",
                "final_url",
                "title",
                "analyzed_at",
                "total_requests",
                "total_hosts",
                "total_ips_measured",
                "ping_success",
                "ping_failed",
                "avg_rtt_avg_ms",
                "max_rtt_avg_ms",
                "traceroute_success",
                "traceroute_failed",
                "ips_with_bgp_match",
            ],
        )
    latest_ip_rows = [
        {
            "hostname": row.get("hostname"),
            "ip": row.get("ip"),
            "bgp_route_count": row.get("bgp_route_count"),
            "ping_status": row.get("ping_status"),
            "loss": row.get("packet_loss_percent"),
            "rtt_avg": row.get("rtt_avg_ms"),
            "rtt_max": row.get("rtt_max_ms"),
            "traceroute_status": row.get("traceroute_status"),
            "hops": row.get("traceroute_hop_count"),
        }
        for row in latest_ip_results
    ]
    _print_table(
        latest_ip_rows,
        ["hostname", "ip", "bgp_route_count", "ping_status", "loss", "rtt_avg", "rtt_max", "traceroute_status", "hops"],
        "Latest Synthetic IP Results",
    )


def cmd_synthetic_host(args: argparse.Namespace) -> None:
    response = _request("GET", f"/synthetic/hosts/{args.hostname}")
    data = _ensure_ok(response)
    host_summary = data.get("host_summary")
    latest_ip_results = data.get("latest_ip_results") or []
    if not host_summary:
        console.print("Host sintético não encontrado.")
        return
    _print_summary_panel(
        "Synthetic Host Summary",
        host_summary,
        [
            "hostname",
            "total_runs",
            "total_ips_measured",
            "avg_rtt_avg_ms",
            "min_rtt_avg_ms",
            "max_rtt_avg_ms",
            "total_bgp_matches",
            "last_seen",
        ],
    )
    latest_ip_rows = [
        {
            "run_id": row.get("run_id"),
            "analyzed_at": row.get("analyzed_at"),
            "url": row.get("url"),
            "final_url": row.get("final_url"),
            "hostname": row.get("hostname"),
            "ip": row.get("ip"),
            "bgp_route_count": row.get("bgp_route_count"),
            "has_bgp_match": row.get("has_bgp_match"),
            "ping_status": row.get("ping_status"),
            "loss": row.get("packet_loss_percent"),
            "rtt_avg": row.get("rtt_avg_ms"),
            "rtt_max": row.get("rtt_max_ms"),
            "traceroute_status": row.get("traceroute_status"),
            "hops": row.get("traceroute_hop_count"),
            "responded": row.get("traceroute_responded_hop_count"),
        }
        for row in latest_ip_results
    ]
    _print_table(
        latest_ip_rows,
        [
            "run_id",
            "analyzed_at",
            "url",
            "final_url",
            "hostname",
            "ip",
            "bgp_route_count",
            "has_bgp_match",
            "ping_status",
            "loss",
            "rtt_avg",
            "rtt_max",
            "traceroute_status",
            "hops",
            "responded",
        ],
        "Latest Synthetic Host IP Results",
    )


def cmd_synthetic_ip_results(args: argparse.Namespace) -> None:
    response = _request("GET", "/synthetic/ip-results", params={"run_id": args.run_id, "limit": args.limit})
    rows = _ensure_ok(response)
    table_rows = [
        {
            "hostname": row.get("hostname"),
            "ip": row.get("ip"),
            "bgp_route_count": row.get("bgp_route_count"),
            "ping_status": row.get("ping_status"),
            "rtt_avg": row.get("rtt_avg_ms"),
            "rtt_max": row.get("rtt_max_ms"),
            "traceroute_status": row.get("traceroute_status"),
            "hops": row.get("traceroute_hop_count"),
        }
        for row in rows
    ]
    _print_table(
        table_rows,
        [
            "hostname",
            "ip",
            "bgp_route_count",
            "ping_status",
            "rtt_avg",
            "rtt_max",
            "traceroute_status",
            "hops",
        ],
        f"Synthetic IP Results - run {args.run_id}",
    )


def cmd_traceroute_latest(args: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/traceroute/latest", params={"limit": args.limit})
    rows = _ensure_ok(response)
    table_rows = [
        {
            "measurement_id": row.get("measurement_id"),
            "target": row.get("target"),
            "label": row.get("target_label"),
            "mode": row.get("mode"),
            "status": row.get("status"),
            "hops": row.get("hop_count"),
            "responded": row.get("responded_hop_count"),
            "measured_at": row.get("measured_at"),
        }
        for row in rows
    ]
    _print_table(
        table_rows,
        ["measurement_id", "target", "label", "mode", "status", "hops", "responded", "measured_at"],
        "Latest Traceroute Measurements",
    )


def cmd_traceroute_summary(_: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/traceroute/summary")
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "target",
            "total_measurements",
            "successful_measurements",
            "failed_measurements",
            "avg_hop_count",
            "avg_responded_hop_count",
            "last_measured_at",
        ],
        "Traceroute Summary",
    )


def cmd_traceroute_hop_summary(_: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/traceroute/hop-summary")
    data = _ensure_ok(response)
    _print_summary_panel(
        "Traceroute Hop Summary",
        data,
        [
            "total_hops",
            "responded_hops",
            "no_response_hops",
            "public_hops",
            "private_hops",
            "cgnat_hops",
            "matched_interface_hops",
            "unmatched_hops",
            "distinct_targets",
            "distinct_hop_ips",
        ],
    )


def cmd_traceroute_classification_summary(_: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/traceroute/classification-summary")
    data = _ensure_ok(response)
    _print_summary_panel(
        "Traceroute Classification Summary",
        data,
        [
            "total_hops",
            "no_response_hops",
            "matched_interface_hops",
            "classified_hops",
            "unmatched_hops",
            "private_unmatched_hops",
            "private_classified_hops",
            "distinct_classified_hop_ips",
            "distinct_unmatched_hop_ips",
        ],
    )


def _print_summary_panel(title: str, data: dict[str, Any], fields: list[str]) -> None:
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("field", style="bold")
    table.add_column("value")
    for field in fields:
        table.add_row(str(field), _format_cli_value(data.get(field), max_length=1200 if field == "answer_summary" else 240))
    console.print(Panel(table, title=title, expand=False))


def cmd_traceroute_history(args: argparse.Namespace) -> None:
    response = _request("GET", f"/measurements/traceroute/history/{args.target}", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "id",
            "target",
            "target_label",
            "source_label",
            "mode",
            "max_hops",
            "timeout_seconds",
            "probes",
            "returncode",
            "status",
            "hop_count",
            "responded_hop_count",
            "measured_at",
        ],
        f"Traceroute History - {args.target}",
    )


def cmd_traceroute_hops(args: argparse.Namespace) -> None:
    response = _request("GET", f"/measurements/traceroute/hops/{args.measurement_id}")
    rows = _ensure_ok(response)
    _print_table(
        rows,
        ["hop_number", "hop_ip", "responded", "rtt_avg_ms", "raw_line"],
        f"Traceroute Hops - Measurement {args.measurement_id}",
    )


def cmd_traceroute_latest_hops_enriched(args: argparse.Namespace) -> None:
    response = _request("GET", f"/measurements/traceroute/latest-hops-enriched/{args.target}")
    rows = _ensure_ok(response)
    _print_table(
        rows,
        ["hop_number", "hop_ip", "ip_scope", "inventory_match_status", "router_hostname", "interface_name", "rtt_avg_ms", "raw_line"],
        f"Latest Traceroute Hops Enriched - {args.target}",
    )


def cmd_traceroute_latest_hops_classified(args: argparse.Namespace) -> None:
    response = _request("GET", f"/measurements/traceroute/latest-hops-classified/{args.target}")
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "hop_number",
            "hop_ip",
            "ip_scope",
            "effective_context_status",
            "hop_classification",
            "classification_confidence",
            "classification_provider",
            "router_hostname",
            "interface_name",
            "rtt_avg_ms",
        ],
        f"Latest Traceroute Hops Classified - {args.target}",
    )


def cmd_traceroute_unmatched_private_hops(args: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/traceroute/unmatched-private-hops", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        ["hop_ip", "ip_scope", "occurrences", "distinct_targets", "avg_rtt_avg_ms", "first_seen", "last_seen"],
        "Unmatched Private Traceroute Hops",
    )


def cmd_traceroute_unclassified_private_hops(args: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/traceroute/unclassified-private-hops", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        ["hop_ip", "ip_scope", "occurrences", "distinct_targets", "avg_rtt_avg_ms", "first_seen", "last_seen"],
        "Unclassified Private Traceroute Hops",
    )


def cmd_traceroute_classified_hops(args: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/traceroute/classified-hops", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "target",
            "hop_number",
            "hop_ip",
            "ip_scope",
            "effective_context_status",
            "hop_classification",
            "classification_confidence",
            "classification_provider",
            "rtt_avg_ms",
        ],
        "Classified Traceroute Hops",
    )


def cmd_traceroute_matched_hops(args: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/traceroute/matched-hops", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        [
            "target",
            "target_label",
            "hop_number",
            "hop_ip",
            "ip_scope",
            "router_hostname",
            "interface_name",
            "interface_description",
            "rtt_avg_ms",
        ],
        "Matched Traceroute Hops",
    )


def cmd_traceroute_latest_hops(args: argparse.Namespace) -> None:
    response = _request("GET", f"/measurements/traceroute/latest-hops/{args.target}")
    rows = _ensure_ok(response)
    _print_table(
        rows,
        ["measurement_id", "target", "target_label", "mode", "measured_at", "hop_number", "hop_ip", "responded", "rtt_avg_ms", "raw_line"],
        f"Latest Traceroute Hops - {args.target}",
    )


def cmd_traceroute_private_hops(args: argparse.Namespace) -> None:
    response = _request("GET", "/measurements/traceroute/private-hops", params={"limit": args.limit})
    rows = _ensure_ok(response)
    _print_table(
        rows,
        ["target", "hop_number", "hop_ip", "rtt_avg_ms", "measured_at"],
        "Private Traceroute Hops",
    )


def cmd_external_routes_services(_: argparse.Namespace) -> None:
    rows = _ensure_ok(_request("GET", "/external-routes/services"))
    _print_table(
        rows,
        [
            "service_slug",
            "display_name",
            "category",
            "target_count",
            "observation_count",
            "hop_count",
            "distinct_asn_count",
            "unknown_hop_count",
            "last_seen_at",
        ],
        "External Route Services",
    )


def cmd_external_routes_service(args: argparse.Namespace) -> None:
    summary = _ensure_ok(_request("GET", f"/external-routes/services/{args.service}/summary"))
    _print_summary_panel(
        f"External Route Summary - {args.service}",
        summary.get("summary") or {},
        [
            "service_slug",
            "display_name",
            "category",
            "is_ptt",
            "target_count",
            "observation_count",
            "hop_count",
            "distinct_asn_count",
            "unknown_hop_count",
            "last_seen_at",
        ],
    )
    _print_table(
        summary.get("hops") or [],
        [
            "hop_ip",
            "asn",
            "organization",
            "country",
            "category",
            "role",
            "confidence",
            "occurrence_count",
            "target_count",
            "min_hop_number",
            "max_hop_number",
            "last_seen_at",
        ],
        f"External Route Hops - {args.service}",
    )
    _print_table(
        summary.get("edges") or [],
        [
            "edge_uid",
            "traceroute_run_ref",
            "from_hop_ip",
            "from_hop_index",
            "to_hop_ip",
            "to_hop_index",
            "from_ip_type",
            "to_ip_type",
            "transition_type",
            "confidence",
            "observed_at",
        ],
        f"External Route Edges - {args.service}",
    )


def cmd_external_routes_trace(args: argparse.Namespace) -> None:
    payload = {
        "confirm": bool(args.confirm),
        "target_override": args.target_override,
        "max_hops": args.max_hops,
    }
    data = _ensure_ok(_request("POST", f"/external-routes/services/{args.service}/trace", json_data=payload))
    _print_summary_panel(
        f"External Route Trace - {args.service}",
        data,
        [
            "status",
            "run_uid",
            "hops_count",
            "edges_count",
            "unknown_count",
            "graph_url",
        ],
    )
    _print_summary_panel(
        "Selected Target",
        data.get("target") or {},
        [
            "target_uid",
            "target_host",
            "target_resolved_ip",
            "target_source",
            "target_selection_reason",
            "target_kind",
        ],
    )
    _print_table(
        data.get("trace", {}).get("hops") or [],
        ["hop_number", "hop_ip", "responded", "rtt_avg_ms", "ip_scope", "raw_line"],
        "Trace Hops",
    )
    _print_table(
        data.get("edges") or [],
        [
            "edge_uid",
            "traceroute_run_ref",
            "from_hop_ip",
            "from_hop_index",
            "to_hop_ip",
            "to_hop_index",
            "from_ip_type",
            "to_ip_type",
            "transition_type",
            "confidence",
        ],
        "Trace Edges",
    )


def cmd_external_routes_hop_context(args: argparse.Namespace) -> None:
    data = _ensure_ok(_request("GET", f"/external-routes/hops/{args.ip}/context"))
    _print_summary_panel(
        f"External Route Hop Context - {args.ip}",
        data,
        [
            "status",
            "confidence_reason",
        ],
    )
    _print_summary_panel(
        "Hop",
        data.get("hop") or {},
        [
            "hop_ip",
            "asn",
            "organization",
            "country",
            "category",
            "role",
            "confidence",
            "observation_count",
            "first_seen_at",
            "last_seen_at",
        ],
    )
    _print_summary_panel(
        "Neighbors",
        {
            "previous_hops": ", ".join(data.get("previous_hops") or []),
            "next_hops": ", ".join(data.get("next_hops") or []),
        },
        ["previous_hops", "next_hops"],
    )
    _print_table(
        data.get("edges_in") or [],
        [
            "edge_uid",
            "service_uid",
            "target_uid",
            "traceroute_run_ref",
            "from_hop_ip",
            "from_hop_index",
            "to_hop_ip",
            "to_hop_index",
            "transition_type",
            "confidence",
        ],
        "Edges In",
    )
    _print_table(
        data.get("edges_out") or [],
        [
            "edge_uid",
            "service_uid",
            "target_uid",
            "traceroute_run_ref",
            "from_hop_ip",
            "from_hop_index",
            "to_hop_ip",
            "to_hop_index",
            "transition_type",
            "confidence",
        ],
        "Edges Out",
    )
    _print_table(
        data.get("sample_paths") or [],
        ["run_uid", "service_uid", "target_uid", "target_host", "hop_number", "hop_index"],
        "Sample Paths",
    )


def cmd_external_routes_hops(args: argparse.Namespace) -> None:
    params: dict[str, Any] = {"limit": args.limit}
    if args.service:
        params["service"] = args.service
    rows = _ensure_ok(_request("GET", "/external-routes/hops", params=params))
    _print_table(
        rows,
        [
            "hop_ip",
            "service_count",
            "services",
            "asn",
            "organization",
            "country",
            "category",
            "role",
            "confidence",
            "observation_count",
            "first_seen_at",
            "last_seen_at",
        ],
        "External Route Hops",
    )


def cmd_external_routes_hop(args: argparse.Namespace) -> None:
    data = _ensure_ok(_request("GET", f"/external-routes/hops/{args.ip}"))
    _print_summary_panel(
        f"External Route Hop - {args.ip}",
        data,
        [
            "hop_ip",
            "service_count",
            "asn",
            "organization",
            "country",
            "category",
            "role",
            "confidence",
            "observation_count",
            "first_seen_at",
            "last_seen_at",
        ],
    )
    _print_table(
        data.get("service_summaries") or [],
        [
            "service_slug",
            "display_name",
            "occurrence_count",
            "target_count",
            "first_seen_at",
            "last_seen_at",
            "category",
            "role",
            "confidence",
        ],
        f"Service Summaries - {args.ip}",
    )


def cmd_external_routes_unknown_hops(args: argparse.Namespace) -> None:
    rows = _ensure_ok(_request("GET", "/external-routes/unknown-hops", params={"limit": args.limit}))
    _print_table(
        rows,
        [
            "hop_ip",
            "service_count",
            "services",
            "asn",
            "organization",
            "country",
            "category",
            "role",
            "confidence",
            "observation_count",
            "last_seen_at",
        ],
        "External Route Unknown Hops",
    )


def cmd_external_routes_compare(args: argparse.Namespace) -> None:
    data = _ensure_ok(
        _request(
            "GET",
            "/external-routes/compare",
            params={"service_a": args.service_a, "service_b": args.service_b},
        )
    )
    comparison = data.get("comparison") or {}
    overlap = comparison.get("overlap") or {}
    _print_summary_panel(
        f"External Route Compare - {args.service_a} vs {args.service_b}",
        overlap,
        [
            "shared_hop_count",
            "shared_asn_count",
            "shared_role_count",
            "shared_category_count",
            "shared_hop_ratio_a",
            "shared_hop_ratio_b",
        ],
    )
    _print_table(
        comparison.get("shared_examples") or [],
        ["hop_ip"],
        "Shared Hop Examples",
    )


def cmd_external_routes_seed_services(_: argparse.Namespace) -> None:
    data = _ensure_ok(_request("POST", "/external-routes/seed-services", json_data={}))
    _print_summary_panel(
        "External Route Seed Services",
        data,
        ["status", "inserted_services", "inserted_targets"],
    )


def cmd_external_routes_ingest_existing(args: argparse.Namespace) -> None:
    data = _ensure_ok(_request("POST", "/external-routes/ingest-existing", json_data={"dry_run": args.dry_run}))
    title = "External Route Ingest Existing (dry-run)" if args.dry_run else "External Route Ingest Existing"
    _print_summary_panel(
        title,
        data,
        [
            "status",
            "dry_run",
            "sources_seen",
            "hops_seen",
        ],
    )
    _print_table(
        data.get("preview") or [],
        ["service", "source_kind", "source_ref", "target_host", "hop_count", "target_hint"],
        "Ingest Preview",
    )


def cmd_external_routes_enrich(args: argparse.Namespace) -> None:
    data = _ensure_ok(_request("POST", "/external-routes/enrich", json_data={"limit": args.limit}))
    _print_summary_panel(
        "External Route Enrich",
        data,
        ["status", "count"],
    )
    _print_table(
        data.get("enriched") or [],
        ["hop", "source"],
        "Enriched Hops",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="routebrain", description="RouteBrain CLI operacional")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("health", help="Valida a API interna").set_defaults(func=cmd_health)
    subparsers.add_parser("summary", help="Mostra resumo geral").set_defaults(func=cmd_summary)

    synthetic_latest = subparsers.add_parser("synthetic-latest", help="Lista relatórios sintéticos mais recentes")
    synthetic_latest.add_argument("--limit", type=int, default=10)
    synthetic_latest.set_defaults(func=cmd_synthetic_latest)

    synthetic_run = subparsers.add_parser("synthetic-run", help="Mostra uma execução sintética por run_id")
    synthetic_run.add_argument("--run-id", type=int, required=True)
    synthetic_run.set_defaults(func=cmd_synthetic_run)

    synthetic_domain = subparsers.add_parser("synthetic-domain", help="Mostra relatório sintético por URL")
    synthetic_domain.add_argument("url", help="URL sintética")
    synthetic_domain.set_defaults(func=cmd_synthetic_domain)

    synthetic_host = subparsers.add_parser("synthetic-host", help="Mostra relatório sintético por host")
    synthetic_host.add_argument("hostname", help="Hostname sintético")
    synthetic_host.set_defaults(func=cmd_synthetic_host)

    synthetic_ip_results = subparsers.add_parser("synthetic-ip-results", help="Lista IPs medidos de uma run sintética")
    synthetic_ip_results.add_argument("--run-id", type=int, required=True)
    synthetic_ip_results.add_argument("--limit", type=int, default=100)
    synthetic_ip_results.set_defaults(func=cmd_synthetic_ip_results)

    ping_latest = subparsers.add_parser("ping-latest", help="Lista últimas medições de ping")
    ping_latest.add_argument("--limit", type=int, default=10)
    ping_latest.set_defaults(func=cmd_ping_latest)

    ping_summary = subparsers.add_parser("ping-summary", help="Resumo de ping por target")
    ping_summary.set_defaults(func=cmd_ping_summary)

    ping_history = subparsers.add_parser("ping-history", help="Histórico de ping por target")
    ping_history.add_argument("target", help="Destino IP")
    ping_history.add_argument("--limit", type=int, default=10)
    ping_history.set_defaults(func=cmd_ping_history)

    peers_ping = subparsers.add_parser("peers-ping", help="Peers observados com ping")
    peers_ping.add_argument("--limit", type=int, default=20)
    peers_ping.set_defaults(func=cmd_peers_ping)

    peers_missing_ping = subparsers.add_parser("peers-missing-ping", help="Peers observados sem ping")
    peers_missing_ping.add_argument("--limit", type=int, default=20)
    peers_missing_ping.set_defaults(func=cmd_peers_missing_ping)

    traceroute_latest = subparsers.add_parser("traceroute-latest", help="Lista últimas medições de traceroute")
    traceroute_latest.add_argument("--limit", type=int, default=10)
    traceroute_latest.set_defaults(func=cmd_traceroute_latest)

    traceroute_summary = subparsers.add_parser("traceroute-summary", help="Resumo de traceroute por target")
    traceroute_summary.set_defaults(func=cmd_traceroute_summary)

    traceroute_hop_summary = subparsers.add_parser("traceroute-hop-summary", help="Resumo de hops de traceroute")
    traceroute_hop_summary.set_defaults(func=cmd_traceroute_hop_summary)

    traceroute_classification_summary = subparsers.add_parser(
        "traceroute-classification-summary", help="Resumo de classificação de traceroute"
    )
    traceroute_classification_summary.set_defaults(func=cmd_traceroute_classification_summary)

    traceroute_history = subparsers.add_parser("traceroute-history", help="Histórico de traceroute por target")
    traceroute_history.add_argument("target", help="Destino IP")
    traceroute_history.add_argument("--limit", type=int, default=10)
    traceroute_history.set_defaults(func=cmd_traceroute_history)

    traceroute_hops = subparsers.add_parser("traceroute-hops", help="Lista hops de uma medição")
    traceroute_hops.add_argument("--measurement-id", type=int, required=True)
    traceroute_hops.set_defaults(func=cmd_traceroute_hops)

    traceroute_latest_hops_enriched = subparsers.add_parser(
        "traceroute-latest-hops-enriched", help="Hops enriquecidos da última medição por target"
    )
    traceroute_latest_hops_enriched.add_argument("target", help="Destino IP")
    traceroute_latest_hops_enriched.set_defaults(func=cmd_traceroute_latest_hops_enriched)

    traceroute_latest_hops_classified = subparsers.add_parser(
        "traceroute-latest-hops-classified", help="Hops classificados da última medição por target"
    )
    traceroute_latest_hops_classified.add_argument("target", help="Destino IP")
    traceroute_latest_hops_classified.set_defaults(func=cmd_traceroute_latest_hops_classified)

    traceroute_unmatched_private_hops = subparsers.add_parser(
        "traceroute-unmatched-private-hops", help="Lista hops privados sem match de inventário"
    )
    traceroute_unmatched_private_hops.add_argument("--limit", type=int, default=20)
    traceroute_unmatched_private_hops.set_defaults(func=cmd_traceroute_unmatched_private_hops)

    traceroute_unclassified_private_hops = subparsers.add_parser(
        "traceroute-unclassified-private-hops", help="Lista hops privados ainda não classificados"
    )
    traceroute_unclassified_private_hops.add_argument("--limit", type=int, default=20)
    traceroute_unclassified_private_hops.set_defaults(func=cmd_traceroute_unclassified_private_hops)

    traceroute_classified_hops = subparsers.add_parser(
        "traceroute-classified-hops", help="Lista hops classificados manualmente"
    )
    traceroute_classified_hops.add_argument("--limit", type=int, default=50)
    traceroute_classified_hops.set_defaults(func=cmd_traceroute_classified_hops)

    traceroute_matched_hops = subparsers.add_parser("traceroute-matched-hops", help="Lista hops com match de inventário")
    traceroute_matched_hops.add_argument("--limit", type=int, default=50)
    traceroute_matched_hops.set_defaults(func=cmd_traceroute_matched_hops)

    traceroute_latest_hops = subparsers.add_parser("traceroute-latest-hops", help="Hops da última medição por target")
    traceroute_latest_hops.add_argument("target", help="Destino IP")
    traceroute_latest_hops.set_defaults(func=cmd_traceroute_latest_hops)

    traceroute_private_hops = subparsers.add_parser("traceroute-private-hops", help="Lista hops privados observados")
    traceroute_private_hops.add_argument("--limit", type=int, default=20)
    traceroute_private_hops.set_defaults(func=cmd_traceroute_private_hops)

    external_routes = subparsers.add_parser("external-routes", help="Inventário de rotas externas por serviço")
    external_routes_subparsers = external_routes.add_subparsers(dest="external_routes_command", required=True)

    external_routes_services = external_routes_subparsers.add_parser("services", help="Lista serviços externos")
    external_routes_services.set_defaults(func=cmd_external_routes_services)

    external_routes_service = external_routes_subparsers.add_parser("service", help="Mostra resumo de um serviço")
    external_routes_service.add_argument("service", help="Slug do serviço")
    external_routes_service.set_defaults(func=cmd_external_routes_service)

    external_routes_trace = external_routes_subparsers.add_parser("trace", help="Executa traceroute controlado por serviço")
    external_routes_trace.add_argument("service", help="Slug do serviço")
    external_routes_trace.add_argument("--confirm", action="store_true", default=False)
    external_routes_trace.add_argument("--target-override", default=None)
    external_routes_trace.add_argument("--max-hops", type=int, default=20)
    external_routes_trace.set_defaults(func=cmd_external_routes_trace)

    external_routes_hops = external_routes_subparsers.add_parser("hops", help="Lista hops inventariados")
    external_routes_hops.add_argument("--service", default=None)
    external_routes_hops.add_argument("--limit", type=int, default=50)
    external_routes_hops.set_defaults(func=cmd_external_routes_hops)

    external_routes_hop = external_routes_subparsers.add_parser("hop", help="Mostra um hop externo")
    external_routes_hop.add_argument("ip", help="IP do hop")
    external_routes_hop.set_defaults(func=cmd_external_routes_hop)

    external_routes_hop_context = external_routes_subparsers.add_parser("hop-context", help="Mostra contexto completo de um hop")
    external_routes_hop_context.add_argument("ip", help="IP do hop")
    external_routes_hop_context.set_defaults(func=cmd_external_routes_hop_context)

    external_routes_unknown_hops = external_routes_subparsers.add_parser(
        "unknown-hops", help="Lista hops externos desconhecidos"
    )
    external_routes_unknown_hops.add_argument("--limit", type=int, default=50)
    external_routes_unknown_hops.set_defaults(func=cmd_external_routes_unknown_hops)

    external_routes_compare = external_routes_subparsers.add_parser("compare", help="Compara dois serviços")
    external_routes_compare.add_argument("service_a", help="Serviço A")
    external_routes_compare.add_argument("service_b", help="Serviço B")
    external_routes_compare.set_defaults(func=cmd_external_routes_compare)

    external_routes_seed = external_routes_subparsers.add_parser("seed-services", help="Seeda serviços externos")
    external_routes_seed.set_defaults(func=cmd_external_routes_seed_services)

    external_routes_ingest = external_routes_subparsers.add_parser(
        "ingest-existing", help="Ingere traceroutes já existentes"
    )
    external_routes_ingest.add_argument("--dry-run", action="store_true", default=False)
    external_routes_ingest.set_defaults(func=cmd_external_routes_ingest_existing)

    external_routes_enrich = external_routes_subparsers.add_parser("enrich", help="Enriquece hops externos")
    external_routes_enrich.add_argument("--limit", type=int, default=100)
    external_routes_enrich.set_defaults(func=cmd_external_routes_enrich)

    latest = subparsers.add_parser("latest-changes", help="Lista mudanças recentes")
    latest.add_argument("--limit", type=int, default=10)
    latest.set_defaults(func=cmd_latest_changes)

    prefix = subparsers.add_parser("prefix", help="Consulta um prefixo")
    prefix.add_argument("prefix", help="Prefixo CIDR")
    prefix.add_argument("--limit", type=int, default=20)
    prefix.set_defaults(func=cmd_prefix)

    ip_lookup = subparsers.add_parser("ip", help="Consulta longest prefix match por IP")
    ip_lookup.add_argument("ip", help="IP IPv4 ou IPv6")
    ip_lookup.set_defaults(func=cmd_ip)

    peer = subparsers.add_parser("peer", help="Consulta um peer")
    peer.add_argument("peer", help="IP do peer ou ASN")
    peer.add_argument("--limit", type=int, default=50)
    peer.set_defaults(func=cmd_peer)

    asn = subparsers.add_parser("asn", help="Consulta um ASN de origem")
    asn.add_argument("asn", type=int)
    asn.add_argument("--limit", type=int, default=50)
    asn.set_defaults(func=cmd_asn)

    top_changes = subparsers.add_parser("top-changes", help="Lista as mudanças mais relevantes")
    top_changes.add_argument("--limit", type=int, default=20)
    top_changes.add_argument("--change-type", default=None)
    top_changes.add_argument("--since-hours", type=int, default=None)
    top_changes.set_defaults(func=cmd_top_changes)

    top_origin_asns = subparsers.add_parser("top-origin-asns", help="Lista origin ASNs mais alterados")
    top_origin_asns.add_argument("--limit", type=int, default=20)
    top_origin_asns.add_argument("--change-type", default=None)
    top_origin_asns.add_argument("--since-hours", type=int, default=None)
    top_origin_asns.set_defaults(func=cmd_top_origin_asns)

    top_peers = subparsers.add_parser("top-peers", help="Lista peers mais alterados")
    top_peers.add_argument("--limit", type=int, default=20)
    top_peers.add_argument("--change-type", default=None)
    top_peers.add_argument("--since-hours", type=int, default=None)
    top_peers.set_defaults(func=cmd_top_peers)

    observed = subparsers.add_parser("observed", help="Coleta e consulta destinos observados")
    observed_subparsers = observed.add_subparsers(dest="observed_command", required=True)

    observed_collect = observed_subparsers.add_parser("collect", help="Executa coleta manual na MikroTik")
    observed_collect.add_argument("--limit", type=int, default=1000)
    observed_collect.add_argument("--dry-run", action="store_true")
    observed_collect.set_defaults(func=cmd_observed_collect)

    observed_enrich = observed_subparsers.add_parser("enrich", help="Enriquece destinos observados pendentes")
    observed_enrich.add_argument("--limit", type=int, default=50)
    observed_enrich.add_argument("--refresh", action="store_true")
    observed_enrich.add_argument("--resolve-bgp", action=argparse.BooleanOptionalAction, default=True)
    observed_enrich.add_argument("--allow-external-asn", action=argparse.BooleanOptionalAction, default=True)
    observed_enrich.set_defaults(func=cmd_observed_enrich)

    observed_pending = observed_subparsers.add_parser("pending", help="Lista destinos com enrichment pendente")
    observed_pending.add_argument("--limit", type=int, default=20)
    observed_pending.set_defaults(func=cmd_observed_pending)

    observed_destinations = observed_subparsers.add_parser("destinations", help="Lista destinos observados")
    observed_destinations.add_argument("--limit", type=int, default=20)
    observed_destinations.set_defaults(func=cmd_observed_destinations)

    observed_asns = observed_subparsers.add_parser("asns", help="Lista ASNs observados")
    observed_asns.add_argument("--limit", type=int, default=20)
    observed_asns.set_defaults(func=cmd_observed_asns)

    observed_categories = observed_subparsers.add_parser("categories", help="Lista categorias observadas")
    observed_categories.add_argument("--limit", type=int, default=20)
    observed_categories.set_defaults(func=cmd_observed_categories)

    observed_promote = observed_subparsers.add_parser("promote", help="Promove um destino observado para baseline")
    observed_promote.add_argument("ip", help="IP do destino")
    observed_promote.add_argument("--confirm", action="store_true")
    observed_promote.add_argument("--notes", default=None)
    observed_promote.set_defaults(func=cmd_observed_promote)

    observed_baselines = observed_subparsers.add_parser("baselines", help="Lista baselines de destinos observados")
    observed_baselines.add_argument("--limit", type=int, default=20)
    observed_baselines.add_argument("--status", default=None)
    observed_baselines.set_defaults(func=cmd_observed_baselines)

    observed_baseline = observed_subparsers.add_parser("baseline", help="Mostra uma baseline por IP")
    observed_baseline.add_argument("ip", help="IP do destino")
    observed_baseline.set_defaults(func=cmd_observed_baseline)

    observed_report = observed_subparsers.add_parser("report", help="Mostra relatório operacional de um destino")
    observed_report.add_argument("ip", help="IP do destino")
    observed_report.set_defaults(func=cmd_observed_report)

    observed_measure = observed_subparsers.add_parser("measure", help="Executa ping/traceroute ativo da baseline")
    observed_measure.add_argument("ip", help="IP do destino")
    observed_measure.add_argument("--confirm", action="store_true")
    observed_measure.set_defaults(func=cmd_observed_measure)

    observed_measurements = observed_subparsers.add_parser("measurements", help="Lista medições de uma baseline")
    observed_measurements.add_argument("ip", help="IP do destino")
    observed_measurements.add_argument("--limit", type=int, default=20)
    observed_measurements.set_defaults(func=cmd_observed_measurements)

    observed_graph = observed_subparsers.add_parser("traceroute-graph", help="Mostra o traceroute graph da última medição")
    observed_graph.add_argument("ip", help="IP do destino")
    observed_graph.set_defaults(func=cmd_observed_traceroute_graph)

    routegraph_report = subparsers.add_parser("routegraph-report", help="Gera relatório local de completude do RouteGraph v1")
    routegraph_report.add_argument("run_uid", help="Identificador da run")
    routegraph_report.add_argument("--format", choices={"text", "json"}, default="text")
    routegraph_report.set_defaults(func=cmd_routegraph_report)

    observed_trends = observed_subparsers.add_parser("trends", help="Lista destinos com tendência temporal")
    observed_trends.add_argument("--limit", type=int, default=20)
    observed_trends.add_argument("--window-runs", type=int, default=10)
    observed_trends.set_defaults(func=cmd_observed_trends)

    observed_trend = observed_subparsers.add_parser("trend", help="Mostra tendência temporal de um destino")
    observed_trend.add_argument("ip", help="IP do destino")
    observed_trend.add_argument("--window-runs", type=int, default=10)
    observed_trend.set_defaults(func=cmd_observed_trend)

    observed_trends_asns = observed_subparsers.add_parser("trends-asns", help="Lista tendências por ASN")
    observed_trends_asns.add_argument("--limit", type=int, default=20)
    observed_trends_asns.add_argument("--window-runs", type=int, default=10)
    observed_trends_asns.set_defaults(func=cmd_observed_trends_asns)

    observed_trends_categories = observed_subparsers.add_parser("trends-categories", help="Lista tendências por categoria")
    observed_trends_categories.add_argument("--limit", type=int, default=20)
    observed_trends_categories.add_argument("--window-runs", type=int, default=10)
    observed_trends_categories.set_defaults(func=cmd_observed_trends_categories)

    observed_trends_summary = observed_subparsers.add_parser("trends-summary", help="Resumo das tendências temporais")
    observed_trends_summary.add_argument("--window-runs", type=int, default=10)
    observed_trends_summary.set_defaults(func=cmd_observed_trends_summary)

    top_prefixes = subparsers.add_parser("top-prefixes", help="Lista prefixos mais alterados")
    top_prefixes.add_argument("--limit", type=int, default=20)
    top_prefixes.add_argument("--change-type", default=None)
    top_prefixes.add_argument("--since-hours", type=int, default=None)
    top_prefixes.set_defaults(func=cmd_top_prefixes)

    enrich = subparsers.add_parser("enrich", help="Enriquece ASN ou IP com fontes externas cacheadas")
    enrich_subparsers = enrich.add_subparsers(dest="enrich_command", required=True)
    enrich_asn = enrich_subparsers.add_parser("asn", help="Enriquece um ASN")
    enrich_asn.add_argument("asn", type=int, help="ASN")
    enrich_asn.add_argument("--refresh", action="store_true", help="Força consulta externa e renova cache")
    enrich_asn.set_defaults(func=cmd_enrich_asn)
    enrich_ip = enrich_subparsers.add_parser("ip", help="Enriquece um IP")
    enrich_ip.add_argument("ip", help="IP")
    enrich_ip.add_argument("--refresh", action="store_true", help="Força consulta externa e renova cache")
    enrich_ip.set_defaults(func=cmd_enrich_ip)

    questions = subparsers.add_parser("questions", help="Mostra perguntas respondíveis e documentação")
    questions.set_defaults(func=cmd_questions)

    semantic = subparsers.add_parser("semantic", help="Gerencia a memória semântica text_fallback")
    semantic_subparsers = semantic.add_subparsers(dest="semantic_command", required=True)

    semantic_rebuild = semantic_subparsers.add_parser("rebuild", help="Reconstrói documentos semânticos")
    semantic_rebuild.add_argument("--scope", default="all")
    semantic_rebuild.add_argument("--limit", type=int, default=None)
    semantic_rebuild.add_argument("--dry-run", action="store_true")
    semantic_rebuild.add_argument("--skip-existing", action="store_true", default=True)
    semantic_rebuild.add_argument("--force", action="store_true")
    semantic_rebuild.set_defaults(func=cmd_semantic_rebuild)

    semantic_search = semantic_subparsers.add_parser("search", help="Busca textual na memória semântica")
    semantic_search.add_argument("query", help="Texto de busca")
    semantic_search.add_argument("--limit", type=int, default=10)
    semantic_search.add_argument("--object-type", default=None)
    semantic_search.set_defaults(func=cmd_semantic_search)

    semantic_health = semantic_subparsers.add_parser("health", help="Valida a camada semântica/vetorial")
    semantic_health.set_defaults(func=cmd_semantic_health)

    semantic_documents = semantic_subparsers.add_parser("documents", help="Lista documentos semânticos")
    semantic_documents.add_argument("--limit", type=int, default=50)
    semantic_documents.add_argument("--object-type", default=None)
    semantic_documents.set_defaults(func=cmd_semantic_documents)

    ask = subparsers.add_parser("ask", help="Cria uma learning request em modo planejado")
    ask.add_argument("question", nargs="+", help="Pergunta operacional")
    ask.add_argument("--operator", default=os.getenv("ROUTEBRAIN_OPERATOR"))
    ask.set_defaults(func=cmd_learning_ask)

    learn = subparsers.add_parser("learn", help="Gerencia learning requests")
    learn_subparsers = learn.add_subparsers(dest="learn_command", required=True)

    learn_request = learn_subparsers.add_parser("request", help="Mostra uma learning request")
    learn_request.add_argument("request_uid", help="Identificador da request")
    learn_request.set_defaults(func=cmd_learning_request)

    learn_approve = learn_subparsers.add_parser("approve", help="Aprova uma learning request")
    learn_approve.add_argument("request_uid", help="Identificador da request")
    learn_approve.set_defaults(func=cmd_learning_approve)

    learn_execute = learn_subparsers.add_parser("execute", help="Executa uma learning request")
    learn_execute.add_argument("request_uid", help="Identificador da request")
    learn_execute.add_argument("--dry-run", dest="dry_run", action="store_true", default=False)
    learn_execute.add_argument("--active", action="store_true", help="Executa medições ativas após approve")
    learn_execute.add_argument("--force-refresh", action="store_true", help="Força refresh das evidências reutilizáveis")
    learn_execute.set_defaults(func=cmd_learning_execute)

    learn_answer = learn_subparsers.add_parser("answer", help="Mostra a resposta construída")
    learn_answer.add_argument("request_uid", help="Identificador da request")
    learn_answer.set_defaults(func=cmd_learning_answer)

    learn_classify = learn_subparsers.add_parser("classify", help="Classifica uma learning request existente")
    learn_classify.add_argument("request_uid", help="Identificador da request")
    learn_classify.set_defaults(func=cmd_learning_classify)

    learn_classifications = learn_subparsers.add_parser("classifications", help="Lista classificações de uma request")
    learn_classifications.add_argument("request_uid", help="Identificador da request")
    learn_classifications.set_defaults(func=cmd_learning_classifications)

    learn_enrich = learn_subparsers.add_parser("enrich", help="Enriquece uma learning request com fontes externas")
    learn_enrich.add_argument("request_uid", help="Identificador da request")
    learn_enrich.add_argument("--refresh", action="store_true", help="Força refresh das fontes externas")
    learn_enrich.add_argument("--no-external", dest="allow_external", action="store_false", default=True)
    learn_enrich.set_defaults(func=cmd_learning_enrich)

    learn_memory = learn_subparsers.add_parser("memory", help="Mostra a memória operacional reutilizável")
    learn_memory_subparsers = learn_memory.add_subparsers(dest="learn_memory_command", required=True)
    learn_memory_domain = learn_memory_subparsers.add_parser("domain", help="Mostra a memória de um domínio")
    learn_memory_domain.add_argument("domain", help="Domínio operacional")
    learn_memory_domain.set_defaults(func=cmd_learning_memory_domain)

    learn_classify_domain = learn_subparsers.add_parser("classify-domain", help="Classifica um domínio operacional")
    learn_classify_domain.add_argument("domain", help="Domínio operacional")
    learn_classify_domain.set_defaults(func=cmd_learning_classify_domain)

    learn_known_networks = learn_subparsers.add_parser("known-networks", help="Lista heurísticas locais de rede")
    learn_known_networks.set_defaults(func=cmd_learning_known_networks)

    learn_search = learn_subparsers.add_parser("search", help="Busca textual sobre a memória semântica de learning")
    learn_search.add_argument("query", help="Texto de busca")
    learn_search.add_argument("--limit", type=int, default=10)
    learn_search.set_defaults(func=cmd_learning_search)

    learn_memory_domain_flat = subparsers.add_parser("learn-memory-domain", help="Mostra a memória de um domínio")
    learn_memory_domain_flat.add_argument("domain", help="Domínio operacional")
    learn_memory_domain_flat.set_defaults(func=cmd_learning_memory_domain)

    learn_classify_domain_flat = subparsers.add_parser("learn-classify-domain", help="Classifica um domínio")
    learn_classify_domain_flat.add_argument("domain", help="Domínio operacional")
    learn_classify_domain_flat.set_defaults(func=cmd_learning_classify_domain)

    learn_known_networks_flat = subparsers.add_parser("learn-known-networks", help="Lista heurísticas locais de rede")
    learn_known_networks_flat.set_defaults(func=cmd_learning_known_networks)

    semantic_rebuild_flat = subparsers.add_parser("semantic-rebuild", help="Reconstrói documentos semânticos")
    semantic_rebuild_flat.add_argument("--scope", default="all")
    semantic_rebuild_flat.add_argument("--limit", type=int, default=None)
    semantic_rebuild_flat.add_argument("--dry-run", action="store_true")
    semantic_rebuild_flat.add_argument("--skip-existing", action="store_true", default=True)
    semantic_rebuild_flat.add_argument("--force", action="store_true")
    semantic_rebuild_flat.set_defaults(func=cmd_semantic_rebuild)

    semantic_search_flat = subparsers.add_parser("semantic-search", help="Busca textual na memória semântica")
    semantic_search_flat.add_argument("query", help="Texto de busca")
    semantic_search_flat.add_argument("--limit", type=int, default=10)
    semantic_search_flat.add_argument("--object-type", default=None)
    semantic_search_flat.set_defaults(func=cmd_semantic_search)

    semantic_health_flat = subparsers.add_parser("semantic-health", help="Valida a camada semântica/vetorial")
    semantic_health_flat.set_defaults(func=cmd_semantic_health)

    semantic_documents_flat = subparsers.add_parser("semantic-documents", help="Lista documentos semânticos")
    semantic_documents_flat.add_argument("--limit", type=int, default=50)
    semantic_documents_flat.add_argument("--object-type", default=None)
    semantic_documents_flat.set_defaults(func=cmd_semantic_documents)

    enrich_asn_flat = subparsers.add_parser("enrich-asn", help="Enriquece um ASN")
    enrich_asn_flat.add_argument("asn", type=int, help="ASN")
    enrich_asn_flat.add_argument("--refresh", action="store_true", help="Força consulta externa e renova cache")
    enrich_asn_flat.set_defaults(func=cmd_enrich_asn)

    enrich_ip_flat = subparsers.add_parser("enrich-ip", help="Enriquece um IP")
    enrich_ip_flat.add_argument("ip", help="IP")
    enrich_ip_flat.add_argument("--refresh", action="store_true", help="Força consulta externa e renova cache")
    enrich_ip_flat.set_defaults(func=cmd_enrich_ip)

    learn_enrich_flat = subparsers.add_parser("learn-enrich", help="Enriquece uma learning request com fontes externas")
    learn_enrich_flat.add_argument("request_uid", help="Identificador da request")
    learn_enrich_flat.add_argument("--refresh", action="store_true", help="Força refresh das fontes externas")
    learn_enrich_flat.add_argument("--no-external", dest="allow_external", action="store_false", default=True)
    learn_enrich_flat.set_defaults(func=cmd_learning_enrich)

    learn_search_flat = subparsers.add_parser("learn-search", help="Busca textual sobre a memória semântica de learning")
    learn_search_flat.add_argument("query", help="Texto de busca")
    learn_search_flat.add_argument("--limit", type=int, default=10)
    learn_search_flat.set_defaults(func=cmd_learning_search)

    unmatched = subparsers.add_parser("unmatched-peers", help="Lista peers sem inventário")
    unmatched.add_argument("--limit", type=int, default=10)
    unmatched.set_defaults(func=cmd_unmatched_peers)

    matched = subparsers.add_parser("matched-peers", help="Lista peers com inventário")
    matched.add_argument("--limit", type=int, default=10)
    matched.set_defaults(func=cmd_matched_peers)

    inventory_sites = subparsers.add_parser("inventory-sites", help="Lista sites do inventário")
    inventory_sites.set_defaults(func=cmd_inventory_sites)

    inventory_site = subparsers.add_parser("inventory-site", help="Mostra um site do inventário")
    inventory_site.add_argument("site_code", help="Código do site")
    inventory_site.set_defaults(func=cmd_inventory_site)

    inventory_hosts = subparsers.add_parser("inventory-hosts", help="Lista hosts do inventário")
    inventory_hosts.add_argument("--site-code", default=None)
    inventory_hosts.add_argument("--role", default=None)
    inventory_hosts.add_argument("--tag", default=None)
    inventory_hosts.add_argument("--limit", type=int, default=100)
    inventory_hosts.set_defaults(func=cmd_inventory_hosts)

    inventory_host = subparsers.add_parser("inventory-host", help="Mostra um host do inventário")
    inventory_host.add_argument("hostname", help="Hostname")
    inventory_host.set_defaults(func=cmd_inventory_host)

    inventory_search = subparsers.add_parser("inventory-search", help="Busca hosts no inventário")
    inventory_search.add_argument("query", help="Texto de busca")
    inventory_search.add_argument("--limit", type=int, default=50)
    inventory_search.set_defaults(func=cmd_inventory_search)

    inventory_peers_unmatched = subparsers.add_parser(
        "inventory-peers-unmatched", help="Lista peers BGP sem vínculo no inventário"
    )
    inventory_peers_unmatched.add_argument("--limit", type=int, default=10)
    inventory_peers_unmatched.set_defaults(func=cmd_inventory_peers_unmatched)

    inventory_peer_links = subparsers.add_parser("inventory-peer-links", help="Lista vínculos peer -> host/interface")
    inventory_peer_links.add_argument("--site-code", default=None)
    inventory_peer_links.add_argument("--peer-ip", default=None)
    inventory_peer_links.add_argument("--peer-asn", type=int, default=None)
    inventory_peer_links.add_argument("--limit", type=int, default=100)
    inventory_peer_links.set_defaults(func=cmd_inventory_peer_links)

    inventory_discover = subparsers.add_parser("inventory-discover", help="Descobre candidatos de hosts internos")
    inventory_discover.add_argument("--source", default="mikrotik", choices=["mikrotik"])
    inventory_discover.add_argument("--dry-run", action="store_true", default=False)
    inventory_discover.add_argument("--limit", type=int, default=500)
    inventory_discover.set_defaults(func=cmd_inventory_discover)

    inventory_candidates = subparsers.add_parser("inventory-candidates", help="Lista candidatos de hosts")
    inventory_candidates.add_argument("--status", default=None)
    inventory_candidates.add_argument("--limit", type=int, default=50)
    inventory_candidates.set_defaults(func=cmd_inventory_candidates)

    inventory_candidate = subparsers.add_parser("inventory-candidate", help="Mostra um candidato de host")
    inventory_candidate.add_argument("candidate_uid", help="UID do candidato")
    inventory_candidate.set_defaults(func=cmd_inventory_candidate)

    inventory_promote_candidate = subparsers.add_parser("inventory-promote-candidate", help="Promove candidato para inventory_hosts")
    inventory_promote_candidate.add_argument("candidate_uid", help="UID do candidato")
    inventory_promote_candidate.add_argument("--site-code", default=None)
    inventory_promote_candidate.add_argument("--confirm", action="store_true", default=False)
    inventory_promote_candidate.set_defaults(func=cmd_inventory_promote_candidate)

    inventory_ignore_candidate = subparsers.add_parser("inventory-ignore-candidate", help="Ignora candidato de host")
    inventory_ignore_candidate.add_argument("candidate_uid", help="UID do candidato")
    inventory_ignore_candidate.add_argument("--reason", default=None)
    inventory_ignore_candidate.add_argument("--confirm", action="store_true", default=False)
    inventory_ignore_candidate.set_defaults(func=cmd_inventory_ignore_candidate)

    inventory = subparsers.add_parser("inventory", help="Inventário de hosts e discovery")
    inventory_subparsers = inventory.add_subparsers(dest="inventory_command", required=True)

    inventory_discover_nested = inventory_subparsers.add_parser("discover", help="Descobre candidatos de hosts internos")
    inventory_discover_nested.add_argument("--source", default="mikrotik", choices=["mikrotik"])
    inventory_discover_nested.add_argument("--dry-run", action="store_true", default=False)
    inventory_discover_nested.add_argument("--limit", type=int, default=500)
    inventory_discover_nested.set_defaults(func=cmd_inventory_discover)

    inventory_candidates_nested = inventory_subparsers.add_parser("candidates", help="Lista candidatos de hosts")
    inventory_candidates_nested.add_argument("--status", default=None)
    inventory_candidates_nested.add_argument("--limit", type=int, default=50)
    inventory_candidates_nested.set_defaults(func=cmd_inventory_candidates)

    inventory_candidate_nested = inventory_subparsers.add_parser("candidate", help="Mostra um candidato de host")
    inventory_candidate_nested.add_argument("candidate_uid", help="UID do candidato")
    inventory_candidate_nested.set_defaults(func=cmd_inventory_candidate)

    inventory_promote_nested = inventory_subparsers.add_parser("promote-candidate", help="Promove candidato para inventory_hosts")
    inventory_promote_nested.add_argument("candidate_uid", help="UID do candidato")
    inventory_promote_nested.add_argument("--site", dest="site_code", default=None)
    inventory_promote_nested.add_argument("--site-code", dest="site_code", default=None)
    inventory_promote_nested.add_argument("--confirm", action="store_true", default=False)
    inventory_promote_nested.set_defaults(func=cmd_inventory_promote_candidate)

    inventory_ignore_nested = inventory_subparsers.add_parser("ignore-candidate", help="Ignora candidato de host")
    inventory_ignore_nested.add_argument("candidate_uid", help="UID do candidato")
    inventory_ignore_nested.add_argument("--reason", default=None)
    inventory_ignore_nested.add_argument("--confirm", action="store_true", default=False)
    inventory_ignore_nested.set_defaults(func=cmd_inventory_ignore_candidate)

    ixbr = subparsers.add_parser("ixbr", help="Descoberta pública do IX.br / PTT")
    ixbr_subparsers = ixbr.add_subparsers(dest="ixbr_command", required=True)

    ixbr_locations = ixbr_subparsers.add_parser("locations", help="Lista localidades IX.br")
    ixbr_locations.set_defaults(func=cmd_ixbr_locations)

    ixbr_participants = ixbr_subparsers.add_parser("participants", help="Lista participantes públicos do IX.br")
    ixbr_participants.add_argument("locality_code", help="Código da localidade, ex: CE")
    ixbr_participants.add_argument("--limit", type=int, default=100)
    ixbr_participants.set_defaults(func=cmd_ixbr_participants)

    ixbr_bgp_summary = ixbr_subparsers.add_parser("bgp-summary", help="Resumo IX.br x BGP")
    ixbr_bgp_summary.add_argument("locality_code", help="Código da localidade, ex: CE")
    ixbr_bgp_summary.set_defaults(func=cmd_ixbr_bgp_summary)

    ixbr_seen_as_origin = ixbr_subparsers.add_parser("seen-as-origin", help="Participantes vistos como origin ASN")
    ixbr_seen_as_origin.add_argument("locality_code", help="Código da localidade, ex: CE")
    ixbr_seen_as_origin.add_argument("--limit", type=int, default=100)
    ixbr_seen_as_origin.set_defaults(func=cmd_ixbr_seen_as_origin)

    ixbr_not_seen_as_origin = ixbr_subparsers.add_parser(
        "not-seen-as-origin", help="Participantes não vistos como origin ASN"
    )
    ixbr_not_seen_as_origin.add_argument("locality_code", help="Código da localidade, ex: CE")
    ixbr_not_seen_as_origin.add_argument("--limit", type=int, default=100)
    ixbr_not_seen_as_origin.set_defaults(func=cmd_ixbr_not_seen_as_origin)

    search = subparsers.add_parser("search-prefix", help="Busca textual por prefixo")
    search.add_argument("query", help="Texto do prefixo")
    search.add_argument("--limit", type=int, default=10)
    search.set_defaults(func=cmd_search_prefix)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
