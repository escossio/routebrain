from __future__ import annotations

from app.services.route_memory_graph_validator import validate_route_memory_graph_payload


def test_valid_payload_with_shared_nodes_and_edges() -> None:
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

    result = validate_route_memory_graph_payload(payload)
    assert result.is_valid is True
    assert result.errors == []
    assert result.summary["shared_nodes_count"] == 2
    assert result.summary["shared_edges_count"] == 1


def test_edge_target_missing_node_invalid() -> None:
    payload = {
        "routes": [{"route_id": "route_1"}],
        "nodes": [{"node_id": "n1", "route_ids": ["route_1"], "shared": False}],
        "edges": [{"edge_id": "e1", "source": "n1", "target": "missing", "route_ids": ["route_1"], "shared": False}],
        "segments": [],
        "divergences": [],
        "legend": [],
    }

    result = validate_route_memory_graph_payload(payload)
    assert result.is_valid is False
    assert any(issue.code == "edge_target_invalid" for issue in result.errors)


def test_shared_true_requires_multiple_route_ids() -> None:
    payload = {
        "routes": [{"route_id": "route_1"}],
        "nodes": [{"node_id": "n1", "route_ids": ["route_1"], "shared": True}],
        "edges": [{"edge_id": "e1", "source": "n1", "target": "n1", "route_ids": ["route_1"], "shared": True}],
        "segments": [{"segment_id": "s1", "segment_type": "silent_gap", "route_ids": ["route_1"], "shared": True}],
        "divergences": [],
        "legend": [],
    }

    result = validate_route_memory_graph_payload(payload)
    assert result.is_valid is False
    assert any(issue.code == "shared_true_single_route" for issue in result.errors)


def test_unknown_shared_node_triggers_warning() -> None:
    payload = {
        "routes": [{"route_id": "route_1"}, {"route_id": "route_2"}],
        "nodes": [{"node_id": "n1", "canonical_key": "unknown:route_1:3", "label": "silent", "node_type": "silent", "route_ids": ["route_1", "route_2"], "shared": True}],
        "edges": [{"edge_id": "e1", "source": "n1", "target": "n1", "route_ids": ["route_1", "route_2"], "shared": True}],
        "segments": [],
        "divergences": [],
        "legend": [],
    }

    result = validate_route_memory_graph_payload(payload)
    assert result.is_valid is True
    assert any(issue.code == "shared_unknown_node" for issue in result.warnings)


def test_unknown_route_id_is_invalid() -> None:
    payload = {
        "routes": [{"route_id": "route_1"}],
        "nodes": [{"node_id": "n1", "route_ids": ["route_2"], "shared": False}],
        "edges": [{"edge_id": "e1", "source": "n1", "target": "n1", "route_ids": ["route_1"], "shared": False}],
        "segments": [],
        "divergences": [],
        "legend": [],
    }

    result = validate_route_memory_graph_payload(payload)
    assert result.is_valid is False
    assert any(issue.code == "unknown_route_id" for issue in result.errors)


def test_missing_required_top_level_key_is_invalid() -> None:
    payload = {"routes": [], "nodes": [], "edges": [], "segments": [], "divergences": []}
    result = validate_route_memory_graph_payload(payload)
    assert result.is_valid is False
    assert any(issue.code == "missing_top_level" for issue in result.errors)
