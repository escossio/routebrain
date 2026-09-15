from __future__ import annotations

import ipaddress
import re
from typing import Any

import psycopg
from psycopg.rows import dict_row

from app.db.connection import get_connection
from app.services.bgp_operational_queries import get_prefix_lookup, lookup_bgp_by_ip


def _normalize_asn(value: int | str | None) -> int | None:
    if value is None:
        return None
    try:
        asn = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return asn if asn >= 0 else None


def _normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _normalize_prefix(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    except ValueError:
        return None


def normalize_as_path(as_path: str | None) -> str:
    return " ".join(str(as_path or "").split()).strip()


def asn_in_as_path(asn: int | str, as_path: str | None) -> bool:
    normalized_asn = _normalize_asn(asn)
    if normalized_asn is None:
        return False
    tokens = re.findall(r"\d+", normalize_as_path(as_path))
    return str(normalized_asn) in tokens


def _fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]


def lookup_ip_prefix(ip: str) -> dict[str, Any] | None:
    normalized_ip = _normalize_ip(ip)
    if normalized_ip is None:
        return None
    return lookup_bgp_by_ip(normalized_ip, limit_peers=20)


def get_best_prefix_match(ip_or_prefix: str) -> dict[str, Any] | None:
    normalized_ip = _normalize_ip(ip_or_prefix)
    if normalized_ip is not None:
        lookup = lookup_bgp_by_ip(normalized_ip, limit_peers=20)
    else:
        normalized_prefix = _normalize_prefix(ip_or_prefix)
        if normalized_prefix is None:
            return None
        lookup = get_prefix_lookup(normalized_prefix, limit=20)
        if lookup is None:
            return None
        lookup = {
            "matched_prefix": normalized_prefix,
            "origin_asn": (lookup.get("current_routes") or [{}])[0].get("origin_asn") if lookup.get("current_routes") else None,
            "origin_type": (lookup.get("current_routes") or [{}])[0].get("origin_type") if lookup.get("current_routes") else None,
            "match_route_count": int((lookup.get("summary") or {}).get("total_current_routes") or 0),
            "peer_count": int((lookup.get("summary") or {}).get("total_peers") or 0),
            "collector_count": int((lookup.get("summary") or {}).get("total_collectors") or 0),
            "sample_peers": [str(row.get("peer_ip") or "") for row in (lookup.get("peer_counts") or [])[:10] if row.get("peer_ip")],
            "sample_as_paths": [str(row.get("as_path") or "").strip() for row in (lookup.get("current_routes") or []) if str(row.get("as_path") or "").strip()],
            "summary": lookup.get("summary") or {},
            "current_routes": lookup.get("current_routes") or [],
            "peer_counts": lookup.get("peer_counts") or [],
        }
    if lookup is None:
        return None
    return {
        "ip": normalized_ip,
        "matched_prefix": lookup.get("matched_prefix"),
        "origin_asn": lookup.get("origin_asn"),
        "origin_type": lookup.get("origin_type"),
        "match_route_count": lookup.get("match_route_count"),
        "peer_count": lookup.get("peer_count"),
        "collector_count": lookup.get("collector_count"),
        "sample_peers": lookup.get("sample_peers") or [],
        "sample_as_paths": lookup.get("sample_as_paths") or [],
        "summary": lookup.get("summary") or {},
        "current_routes": lookup.get("current_routes") or [],
        "peer_counts": lookup.get("peer_counts") or [],
    }


def get_routes_covering_ip(ip_or_prefix: str, limit: int = 20) -> list[dict[str, Any]]:
    prefix_lookup = get_best_prefix_match(ip_or_prefix)
    if not prefix_lookup or not prefix_lookup.get("matched_prefix"):
        return []
    prefix = str(prefix_lookup["matched_prefix"])
    lookup = get_prefix_lookup(prefix, limit=limit) or {}
    current_routes = lookup.get("current_routes") or []
    return [row for row in current_routes if isinstance(row, dict)]


def analyze_asn_visibility_for_ip(asn: int | str | None, ip_or_prefix: str, limit: int = 10) -> dict[str, Any]:
    normalized_asn = _normalize_asn(asn)
    normalized_ip = _normalize_ip(ip_or_prefix)
    normalized_prefix = _normalize_prefix(ip_or_prefix)
    if normalized_ip is None and normalized_prefix is None:
        raise ValueError("IP ou prefixo inválido.")

    best_prefix = get_best_prefix_match(ip_or_prefix)
    if best_prefix is None:
        return {
            "asn": normalized_asn,
            "ip": normalized_ip,
            "prefix": normalized_prefix,
            "direct_view_available": False,
            "asn_is_origin": None,
            "asn_seen_in_as_path": None,
            "asn_seen_as_peer": None,
            "peer_asn_lookup_available": True,
            "limitations": ["no_bgp_match_for_ip"],
            "best_prefix": None,
            "routes": [],
            "sample_as_paths": [],
        }

    matched_prefix = str(best_prefix.get("matched_prefix") or normalized_prefix or "")
    prefix_lookup = get_prefix_lookup(matched_prefix, limit=limit) or {}
    current_routes = [row for row in (prefix_lookup.get("current_routes") or []) if isinstance(row, dict)]
    peer_counts = prefix_lookup.get("peer_counts") or []
    route_count = int((prefix_lookup.get("summary") or {}).get("total_current_routes") or len(current_routes) or 0)
    peer_count = int((prefix_lookup.get("summary") or {}).get("total_peers") or len(peer_counts) or 0)

    origin_asn = best_prefix.get("origin_asn")
    asn_is_origin = None if origin_asn is None else int(origin_asn) == normalized_asn
    as_paths = [normalize_as_path(row.get("as_path")) for row in current_routes if normalize_as_path(row.get("as_path"))]
    as_paths = list(dict.fromkeys(as_paths))
    asn_seen_in_as_path = None
    asn_path_examples: list[str] = []
    asn_token = str(normalized_asn)
    for path in as_paths:
        if asn_in_as_path(normalized_asn, path):
            asn_seen_in_as_path = True
            asn_path_examples.append(path)
    if asn_seen_in_as_path is None:
        asn_seen_in_as_path = False

    direct_view_available = False
    asn_seen_as_peer: bool | None = None
    peer_asn_lookup_available = True
    try:
        direct_view_rows = _fetch_all(
            """
            select
              count(*)::bigint as total_routes,
              count(distinct prefix)::bigint as total_prefixes,
              count(distinct peer_ip)::bigint as total_peers
            from bgp_current_routes
            where peer_asn = %s
              and prefix = %s::cidr;
            """,
            (normalized_asn, matched_prefix),
        )
        direct_view_row = direct_view_rows[0] if direct_view_rows else {}
        direct_view_available = int(direct_view_row.get("total_routes") or 0) > 0
        asn_seen_as_peer = int(direct_view_row.get("total_routes") or 0) > 0
    except psycopg.Error:
        limitations: list[str] = ["peer_asn_not_available"]
        if asn_seen_in_as_path is False:
            limitations.append("asn_not_observed_in_sampled_as_paths")
        if not as_paths:
            limitations.append("no_as_path_sample_available")
        peer_names = [str(row.get("peer_ip") or "") for row in peer_counts[:10] if row.get("peer_ip")]
        return {
            "asn": normalized_asn,
            "ip": normalized_ip,
            "prefix": normalized_prefix,
            "matched_prefix": matched_prefix,
            "origin_asn": origin_asn,
            "origin_type": best_prefix.get("origin_type"),
            "route_count": route_count,
            "peer_count": peer_count,
            "asn_is_origin": asn_is_origin,
            "asn_seen_in_as_path": asn_seen_in_as_path,
            "asn_seen_as_peer": None,
            "direct_view_available": False,
            "peer_asn_lookup_available": False,
            "sample_as_paths": as_paths[:10],
            "sample_peers": peer_names,
            "routes": current_routes[:limit],
            "limitations": limitations,
            "best_prefix": best_prefix,
        }
    limitations: list[str] = []
    if not direct_view_available:
        limitations.append("no_direct_peer_view_for_asn")
    if asn_seen_in_as_path is False:
        limitations.append("asn_not_observed_in_sampled_as_paths")
    if not as_paths:
        limitations.append("no_as_path_sample_available")

    peer_names = [str(row.get("peer_ip") or "") for row in peer_counts[:10] if row.get("peer_ip")]
    return {
        "asn": normalized_asn,
        "ip": normalized_ip,
        "prefix": normalized_prefix,
        "matched_prefix": matched_prefix,
        "origin_asn": origin_asn,
        "origin_type": best_prefix.get("origin_type"),
        "route_count": route_count,
        "peer_count": peer_count,
        "asn_is_origin": asn_is_origin,
        "asn_seen_in_as_path": asn_seen_in_as_path,
        "asn_seen_as_peer": asn_seen_as_peer,
        "direct_view_available": direct_view_available,
        "peer_asn_lookup_available": peer_asn_lookup_available,
        "sample_as_paths": as_paths[:10],
        "sample_peers": peer_names,
        "routes": current_routes[:limit],
        "limitations": limitations,
        "best_prefix": best_prefix,
    }


def build_bgp_visibility_response(
    ip_or_prefix: str,
    *,
    asn: int | None = None,
    limit: int = 10,
    include_paths: bool = True,
    include_peers: bool = True,
) -> dict[str, Any]:
    answer = build_asn_ip_visibility_answer(asn, ip_or_prefix, limit=limit)
    payload = {
        "status": "ok",
        "query": {
            "ip": answer.get("bgp_visibility", {}).get("ip") or ip_or_prefix,
            "asn": answer.get("bgp_visibility", {}).get("asn"),
            "prefix": answer.get("bgp_visibility", {}).get("prefix"),
            "limit": limit,
            "include_paths": include_paths,
            "include_peers": include_peers,
        },
        "match": {
            "matched": bool(answer.get("bgp_visibility", {}).get("matched_prefix")),
            "prefix": answer.get("bgp_visibility", {}).get("matched_prefix"),
            "origin_asn": answer.get("bgp_visibility", {}).get("origin_asn"),
            "route_count": answer.get("bgp_visibility", {}).get("route_count"),
            "peer_count": answer.get("bgp_visibility", {}).get("peer_count"),
        },
        "asn_visibility": {
            "asn": answer.get("bgp_visibility", {}).get("asn"),
            "asn_is_origin": answer.get("bgp_visibility", {}).get("asn_is_origin"),
            "asn_seen_in_as_path": answer.get("bgp_visibility", {}).get("asn_seen_in_as_path"),
            "asn_seen_as_peer": answer.get("bgp_visibility", {}).get("asn_seen_as_peer"),
            "direct_view_available": answer.get("bgp_visibility", {}).get("direct_view_available"),
            "as_path_match_count": len(answer.get("bgp_visibility", {}).get("sample_as_paths") or []),
            "peer_match_count": len(answer.get("bgp_visibility", {}).get("sample_peers") or []),
        },
        "limitations": list(answer.get("bgp_visibility", {}).get("limitations") or []),
        "explanation": answer.get("operational_answer"),
        "observed_routes": [],
        "as_path_examples": [],
    }
    if include_peers:
        payload["observed_routes"] = [
            {
                "prefix": row.get("prefix"),
                "peer_ip": row.get("peer_ip"),
                "origin_asn": row.get("origin_asn"),
                "as_path": normalize_as_path(row.get("as_path")),
                "asn_in_path": asn_in_as_path(answer.get("bgp_visibility", {}).get("asn") or 0, row.get("as_path"))
                if answer.get("bgp_visibility", {}).get("asn") is not None
                else None,
            }
            for row in (answer.get("bgp_visibility", {}).get("sample_routes") or [])
        ][:limit]
    if include_paths:
        payload["as_path_examples"] = [
            {
                "as_path": path,
                "peer_ip": next(
                    (
                        row.get("peer_ip")
                        for row in (answer.get("bgp_visibility", {}).get("sample_routes") or [])
                        if normalize_as_path(row.get("as_path")) == path
                    ),
                    None,
                ),
                "prefix": answer.get("bgp_visibility", {}).get("matched_prefix"),
            }
            for path in (answer.get("bgp_visibility", {}).get("sample_as_paths") or [])[:limit]
        ]
    if not payload["match"]["matched"]:
        payload["limitations"] = sorted(set(payload["limitations"] + ["no_bgp_match_for_ip"]))
    return payload


def build_asn_ip_visibility_answer(asn: int | str | None, ip_or_prefix: str, limit: int = 10) -> dict[str, Any]:
    analysis = analyze_asn_visibility_for_ip(asn, ip_or_prefix, limit=limit)
    normalized_asn = analysis["asn"]
    normalized_ip = analysis["ip"] or analysis.get("prefix") or ip_or_prefix
    matched_prefix = analysis.get("matched_prefix")
    origin_asn = analysis.get("origin_asn")
    asn_is_origin = analysis.get("asn_is_origin")
    asn_seen_in_as_path = analysis.get("asn_seen_in_as_path")
    direct_view_available = analysis.get("direct_view_available")
    limitations = analysis.get("limitations") or []
    if matched_prefix is None:
        operational_answer = (
            f"Não encontrei rota BGP cobrindo esse IP na base atual do RouteBrain; por isso não posso afirmar como o ASN informado enxerga esse destino."
        )
        confidence = "inconclusive"
    else:
        origin_text = f"O IP {normalized_ip} está coberto pelo prefixo {matched_prefix}"
        if origin_asn is not None:
            origin_text += f", originado pelo ASN {origin_asn}"
        origin_text += ". "
        if direct_view_available:
            visibility_text = (
                f"Tenho visão direta do ASN {normalized_asn} como ponto de observação nessa cobertura. "
            )
        else:
            visibility_text = (
                f"Não tenho visão direta do ASN {normalized_asn} como ponto de observação nessa cobertura; "
                "a leitura é inferida pelos AS paths e peers observados pelo RouteBrain. "
            )
        if asn_is_origin is True:
            asn_text = f"O ASN {normalized_asn} é a origem observada desse prefixo."
        elif asn_is_origin is False:
            asn_text = f"O ASN {normalized_asn} não aparece como origem desse prefixo."
        else:
            asn_text = f"Não consigo afirmar se o ASN {normalized_asn} é a origem desse prefixo."
        if asn_seen_in_as_path is True:
            path_text = f"O ASN {normalized_asn} aparece em pelo menos um AS path observado."
        elif asn_seen_in_as_path is False:
            path_text = f"Não encontrei o ASN {normalized_asn} nos AS paths amostrados para esse prefixo."
        else:
            path_text = f"Não consegui confirmar presença do ASN {normalized_asn} nos AS paths observados."
        operational_answer = f"{origin_text}{visibility_text}{asn_text} {path_text}"
        confidence = "high" if direct_view_available and asn_seen_in_as_path is not None else "medium"

    if not direct_view_available:
        limitations.append("no_direct_asn_observation_point")
    if analysis.get("peer_asn_lookup_available") is False:
        limitations.append("peer_asn_not_available")

    return {
        "asn": normalized_asn,
        "ip": normalized_ip,
        "intent": "bgp_asn_ip_visibility",
        "operational_answer": operational_answer,
        "answer": operational_answer,
        "confidence": confidence,
        "bgp_visibility": {
            "asn": normalized_asn,
            "ip": normalized_ip,
            "prefix": analysis.get("prefix"),
            "matched_prefix": matched_prefix,
            "origin_asn": origin_asn,
            "route_count": analysis.get("route_count"),
            "peer_count": analysis.get("peer_count"),
            "asn_is_origin": asn_is_origin,
            "asn_seen_in_as_path": asn_seen_in_as_path,
            "asn_seen_as_peer": analysis.get("asn_seen_as_peer"),
            "direct_view_available": direct_view_available,
            "peer_asn_lookup_available": analysis.get("peer_asn_lookup_available"),
            "sample_as_paths": analysis.get("sample_as_paths") or [],
            "sample_peers": analysis.get("sample_peers") or [],
            "sample_routes": analysis.get("routes") or [],
            "limitations": limitations,
        },
        "recommended_actions": [
            {
                "id": "show_bgp_route_for_ip",
                "label": "Ver rota BGP do IP",
                "description": "Consultar o prefixo e a rota observada na base BGP.",
                "requires_confirmation": False,
                "risk": "read_only",
                "enabled": True,
            },
            {
                "id": "check_asn_in_as_path",
                "label": "Verificar ASN no AS path",
                "description": "Checar se o ASN consultado aparece no caminho observado.",
                "requires_confirmation": False,
                "risk": "read_only",
                "enabled": matched_prefix is not None,
            },
            {
                "id": "generate_asn_ip_visibility_report",
                "label": "Gerar relatório ASN/IP",
                "description": "Consolidar prefixo, origem, peers, AS paths e limitações.",
                "requires_confirmation": False,
                "risk": "read_only_report",
                "enabled": True,
            },
            {
                "id": "add_asn_to_monitoring",
                "label": "Adicionar ASN ao monitoramento",
                "description": "Monitorar mudanças futuras desse ASN sem afetar a análise atual.",
                "requires_confirmation": True,
                "risk": "state_change_monitoring",
                "enabled": True,
            },
        ],
        "asn_ip_visibility": analysis,
    }
