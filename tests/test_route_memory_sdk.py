from __future__ import annotations

from app.services.route_memory_sdk import (
    RouteMemoryGraphSnapshot,
    build_grafana_divergence_rows,
    build_grafana_edge_rows,
    build_grafana_node_rows,
    build_grafana_summary,
    build_sdk_payload,
)
from app.services.route_memory_graph_validator import validate_route_memory_graph_payload


def _snapshot() -> RouteMemoryGraphSnapshot:
    payload = {
        "routes": [
            {"route_id": "route_1", "observation_uid": "rmo_1", "target": "8.8.8.8", "source_node": "example-server", "label": "Route 1"},
            {"route_id": "route_2", "observation_uid": "rmo_2", "target": "8.8.8.8", "source_node": "example-server", "label": "Route 2"},
        ],
        "nodes": [
            {"node_id": "n1", "canonical_key": "ip:1.1.1.1", "label": "1.1.1.1", "node_type": "hop", "ip": "1.1.1.1", "asn": None, "segment_type": "private", "route_ids": ["route_1", "route_2"], "shared": True, "source_node_ids": ["raw1"], "evidence": []},
            {"node_id": "n2", "canonical_key": "ip:2.2.2.2", "label": "2.2.2.2", "node_type": "hop", "ip": "2.2.2.2", "asn": None, "segment_type": "private", "route_ids": ["route_1", "route_2"], "shared": True, "source_node_ids": ["raw2"], "evidence": []},
        ],
        "edges": [
            {"edge_id": "e1", "source": "n1", "target": "n2", "source_key": "ip:1.1.1.1", "target_key": "ip:2.2.2.2", "edge_type": "route_hop", "route_ids": ["route_1", "route_2"], "shared": True, "evidence": []},
        ],
        "segments": [
            {"segment_id": "s1", "segment_type": "private", "segment_fingerprint": "segment:private", "route_ids": ["route_1", "route_2"], "shared": True, "start_hop": 1, "end_hop": 2, "evidence": []},
        ],
        "divergences": [
            {"divergence_id": "d1", "divergence_type": "structural_divergence", "route_ids": ["route_1", "route_2"], "at_segment": "s1", "summary": "shared shape", "severity": "info"},
        ],
        "legend": [{"key": "shared", "label": "Shared"}],
    }
    validation = validate_route_memory_graph_payload(payload)
    return RouteMemoryGraphSnapshot(
        graph_uid="rmg_test",
        source_node="example-server",
        title="RouteMemory graph",
        graph_type="route_memory_graph",
        route_count=2,
        schema_version="route_memory_graph.v1",
        created_at="2026-06-24T00:19:49Z",
        payload=payload,
        validation=validation,
    )


def test_sdk_summary_and_validation_status() -> None:
    snapshot = _snapshot()
    summary = build_grafana_summary(snapshot)
    assert summary["graph_uid"] == "rmg_test"
    assert summary["routes_count"] == 2
    assert summary["nodes_count"] == 2
    assert summary["edges_count"] == 1
    assert summary["validation_status"] == "valid"
    sdk_payload = build_sdk_payload(snapshot)
    assert sdk_payload["summary"]["graph_uid"] == "rmg_test"


def test_sdk_node_rows() -> None:
    snapshot = _snapshot()
    nodes = build_grafana_node_rows(snapshot)
    assert len(nodes) == 2
    assert nodes[0]["id"] == "n1"
    assert nodes[0]["title"] == "1.1.1.1"
    assert nodes[0]["detail__route_ids"] == ["route_1", "route_2"]
    assert nodes[0]["detail__shared"] is True


def test_sdk_edge_rows() -> None:
    snapshot = _snapshot()
    edges = build_grafana_edge_rows(snapshot)
    assert len(edges) == 1
    assert edges[0]["id"] == "e1"
    assert edges[0]["source"] == "n1"
    assert edges[0]["target"] == "n2"
    assert edges[0]["detail__route_ids"] == ["route_1", "route_2"]
    assert edges[0]["detail__shared"] is True


def test_sdk_divergence_rows() -> None:
    snapshot = _snapshot()
    divergences = build_grafana_divergence_rows(snapshot)
    assert len(divergences) == 1
    assert divergences[0]["divergence_type"] == "structural_divergence"
    assert divergences[0]["route_ids"] == ["route_1", "route_2"]
    assert divergences[0]["summary"] == "shared shape"


def test_sdk_reflects_invalid_validation() -> None:
    payload = {
        "routes": [],
        "nodes": [],
        "edges": [],
        "segments": [],
        "divergences": [],
        "legend": [],
    }
    validation = validate_route_memory_graph_payload(payload)
    snapshot = RouteMemoryGraphSnapshot(
        graph_uid="rmg_bad",
        source_node="example-server",
        title="bad",
        graph_type="route_memory_graph",
        route_count=0,
        schema_version="route_memory_graph.v1",
        created_at="2026-06-24T00:19:49Z",
        payload=payload,
        validation=validation,
    )
    summary = build_grafana_summary(snapshot)
    assert summary["validation_status"] == "invalid"
    assert summary["validation_errors_count"] > 0
