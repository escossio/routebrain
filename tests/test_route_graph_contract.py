from __future__ import annotations

import pytest
from fastapi import HTTPException
from app.services import traceroute_graph

import app.api.route_graph as route_graph_api
from app.adapters.route_graph_cytoscape import route_graph_to_cytoscape
from app.services import route_graph_builder
from app.services.route_graph_builder import build_route_graph_v1, _node_diagnostics
from app.services.route_graph_validator import validate_route_graph


@pytest.fixture(autouse=True)
def offline_bgp_reference(monkeypatch):
    """Contract tests use an empty reference; evidence tests override it explicitly."""
    monkeypatch.setattr(route_graph_builder, "lookup_bgp_by_ip", lambda ip: None)


def _graph(hops):
    return build_route_graph_v1({"run_uid": "run-1", "target": "8.8.8.8", "hops": hops})


def test_simple_three_hop_route():
    graph = _graph(
        [
            {"hop_number": 1, "ip": "10.0.0.1", "asn": None, "organization": "Local ISP", "role": "private"},
            {"hop_number": 2, "ip": "203.0.113.1", "asn": 64500, "organization": "Transit AS"},
            {"hop_number": 3, "ip": "8.8.8.8", "asn": 15169, "organization": "Google", "is_destination": True},
        ]
    )
    valid, errors = validate_route_graph(graph)
    assert valid, errors
    assert graph["summary"]["logical_hop_count"] == 3
    assert len(graph["edges"]) == 2
    assert graph["nodes"][0]["is_private"] is True
    assert graph["nodes"][2]["is_destination"] is True
    assert graph["nodes"][1]["asn"] == 64500
    assert graph["nodes"][2]["as_name"] == "Google"
    assert not any("hop 1 público sem ASN disponível." == warning for warning in graph["warnings"])
    assert not any("hop 1 público sem latência disponível." == warning for warning in graph["warnings"])


def test_silent_hop_is_explicit():
    graph = _graph(
        [
            {"hop_number": 1, "ip": "10.21.0.1"},
            {"hop_number": 2},
            {"hop_number": 3, "ip": "8.8.8.8", "is_destination": True},
        ]
    )
    assert graph["summary"]["silent_hop_count"] == 1
    assert any(node["is_silent"] for node in graph["nodes"])
    assert any("sem resposta explícita" in warning for warning in graph["warnings"])


def test_private_and_public_ip_flags():
    graph = _graph(
        [
            {"hop_number": 1, "ip": "10.0.0.1"},
            {"hop_number": 2, "ip": "1.1.1.1", "is_destination": True},
        ]
    )
    assert graph["nodes"][0]["is_private"] is True
    assert graph["nodes"][1]["is_private"] is False
    assert graph["nodes"][0]["kind"] == "private_hop"
    assert graph["nodes"][1]["kind"] == "destination"


def test_validator_rejects_missing_node_for_edge():
    graph = _graph([{"hop_number": 1, "ip": "1.1.1.1"}])
    graph["edges"].append({"id": "edge-bad", "source": "hop-1", "target": "hop-999", "kind": "logical_next_hop"})
    valid, errors = validate_route_graph(graph)
    assert not valid
    assert any("edge.target inválido" in error for error in errors)


def test_missing_fields_remain_null():
    graph = _graph([{"hop_number": 1, "ip": "1.1.1.1"}])
    assert graph["nodes"][0]["asn"] is None
    assert graph["nodes"][0]["as_name"] is None
    assert graph["nodes"][0]["latency_ms"] is None
    assert graph["nodes"][0]["confidence"] in {"low", "unknown"}


def test_cytoscape_adapter_returns_expected_shape():
    graph = _graph([{"hop_number": 1, "ip": "1.1.1.1"}, {"hop_number": 2, "ip": "8.8.8.8", "is_destination": True}])
    cytoscape = route_graph_to_cytoscape(graph)
    assert cytoscape["layout"]["name"] == "breadthfirst"
    assert cytoscape["layout"]["directed"] is True
    assert len(cytoscape["elements"]) == 3
    node_data = cytoscape["elements"][0]["data"]
    assert "confidence" in node_data
    assert "is_private" in node_data
    assert "evidence_count" in node_data


def test_public_hop_includes_bgp_evidence(monkeypatch):
    monkeypatch.setattr(
        route_graph_builder,
        "lookup_bgp_by_ip",
        lambda ip: {
            "matched_prefix": "1.1.1.0/24",
            "origin_asn": 13335,
            "sample_as_paths": ["49788 13335"],
            "current_routes": [{"as_path": "49788 13335"}],
        },
    )
    graph = _graph([{"hop_number": 1, "ip": "1.1.1.1"}])
    node = graph["nodes"][0]
    assert node["asn"] == 13335
    assert node["bgp_evidence"]["matched_prefix"] == "1.1.1.0/24"
    assert node["bgp_evidence"]["origin_asn"] == 13335
    assert node["bgp_evidence"]["as_path"] == "49788 13335"
    assert node["bgp_evidence"]["source"] == "bgp_current_routes_lpm"
    assert node["bgp_evidence"]["attribution_scope"] == "public_ip"

    cytoscape = route_graph_to_cytoscape(graph)
    node_data = cytoscape["elements"][0]["data"]
    assert node_data["bgp_matched_prefix"] == "1.1.1.0/24"
    assert node_data["bgp_origin_asn"] == 13335
    assert node_data["bgp_source"] == "bgp_current_routes_lpm"


def test_private_hop_keeps_asn_null_and_uses_context(monkeypatch):
    monkeypatch.setattr(
        route_graph_builder,
        "lookup_bgp_by_ip",
        lambda ip: (_ for _ in ()).throw(AssertionError("lookup_bgp_by_ip should not be called for private IPs")),
    )
    graph = _graph([{"hop_number": 1, "ip": "10.20.0.1"}])
    node = graph["nodes"][0]
    assert node["asn"] is None
    assert "bgp_evidence" not in node
    assert node["bgp_context"]["status"] == "private_ip_no_direct_bgp_attribution"
    assert node["bgp_context"]["reason"] == "private_or_cgnat_ip"

    cytoscape = route_graph_to_cytoscape(graph)
    node_data = cytoscape["elements"][0]["data"]
    assert node_data["bgp_evidence"] is None
    assert node_data["bgp_context"]["status"] == "private_ip_no_direct_bgp_attribution"


def test_diagnostics_summary_counts_missing_fields():
    # One observed hop has explicit synthetic evidence; the silent hop has none.
    graph = _graph([
        {"hop_number": 1, "ip": "1.1.1.1", "evidence": [{"source": "synthetic_observation"}]},
        {"hop_number": 2},
    ])
    diagnostics = _node_diagnostics(graph)
    assert diagnostics["total_nodes"] == 2
    assert diagnostics["total_edges"] == 1
    assert diagnostics["missing_asn_count"] == 2
    assert diagnostics["missing_latency_count"] == 2
    assert diagnostics["missing_evidence_count"] == 1


def test_route_graph_source_falls_back_to_external_inventory(monkeypatch):
    calls = []

    def local_lookup(run_id):
        calls.append(("local", run_id))
        return {"available": False}

    def external_lookup(run_uid):
        calls.append(("external", run_uid))
        return {
            "available": True,
            "target": "8.8.8.8",
            "nodes": [{"ip": "1.1.1.1"}, {"ip": "8.8.8.8"}],
        }

    monkeypatch.setattr(traceroute_graph, "get_traceroute_graph_by_run", local_lookup)
    monkeypatch.setattr(route_graph_api, "get_external_route_trace_graph", external_lookup)
    payload = route_graph_api._source_payload_for_run("7")
    assert payload["run_uid"] == "7"
    assert payload["target"] == "8.8.8.8"
    assert payload["hops"][0]["ip"] == "1.1.1.1"
    assert len(payload["hops"]) == 2
    assert calls == [("local", 7), ("external", "7")]


def test_route_graph_source_prefers_local_run(monkeypatch):
    monkeypatch.setattr(
        traceroute_graph, "get_traceroute_graph_by_run",
        lambda run_id: {"available": True, "target": "1.1.1.1", "nodes": [{"ip": "1.1.1.1"}]},
    )

    def unexpected_external(run_uid):
        raise AssertionError("Available local run must not use external fallback")

    monkeypatch.setattr(route_graph_api, "get_external_route_trace_graph", unexpected_external)
    payload = route_graph_api._source_payload_for_run("7")
    assert payload["target"] == "1.1.1.1"
    assert payload["hops"] == [{"ip": "1.1.1.1"}]


def test_route_graph_source_missing_run_returns_404(monkeypatch):
    monkeypatch.setattr(traceroute_graph, "get_traceroute_graph_by_run", lambda run_id: {"available": False})
    monkeypatch.setattr(route_graph_api, "get_external_route_trace_graph", lambda run_uid: {"available": False})
    with pytest.raises(HTTPException) as failure:
        route_graph_api._source_payload_for_run("7")
    assert failure.value.status_code == 404
