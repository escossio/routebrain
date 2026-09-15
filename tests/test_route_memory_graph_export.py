from __future__ import annotations

from copy import deepcopy

import pytest

from app.services.route_memory_graph_export import build_route_memory_graph_payload


def _report(
    observation_uid: str,
    target: str,
    resolved_ip: str,
    segment_suffix: str,
    hops: list[dict[str, object]] | None = None,
    hop_facts: list[dict[str, object]] | None = None,
):
    return {
        "observation_uid": observation_uid,
        "target": target,
        "resolved_ip": resolved_ip,
        "observed_segments": [
            {
                "observed_segment_uid": f"segment-{segment_suffix}",
                "segment_type": "operator_private_core",
                "start_hop": 2,
                "end_hop": 4,
                "structural_fingerprint": "operator_private_core:core",
                "confidence": "medium",
                "human_summary": "Private operator segment observed across multiple routes",
                "context_asn": None,
                "evidence": {"kind": "synthetic"},
            }
        ],
        "hops": hops
        or [
            {
                "hop_index": 1,
                "ip": "10.20.0.1",
                "raw_host": "gw",
                "hop_type": "local_lan",
                "confidence": "high",
                "evidence": {"kind": "synthetic"},
            },
            {
                "hop_index": 2,
                "ip": "10.0.0.2",
                "raw_host": "private-hop",
                "hop_type": "operator_private_core",
                "confidence": "medium",
                "evidence": {"kind": "synthetic"},
            },
        ],
        "hop_facts": hop_facts
        or [
            {
                "observation_uid": observation_uid,
                "hop_index": 2,
                "ip": None,
                "raw_host": "private-hop",
                "hop_type": "unknown",
                "confidence": "low",
                "evidence": [],
            },
            {
                "observation_uid": observation_uid,
                "hop_index": 2,
                "ip": "10.0.0.2",
                "raw_host": "private-hop",
                "hop_type": "public",
                "origin_asn": 64510,
                "confidence": "medium",
                "evidence": ["bgp"],
            },
        ],
    }


def _route_pair_payload(route_1_hops, route_2_hops, *, route_1_facts=None, route_2_facts=None):
    # Explicit route fixtures must not inherit unrelated default facts for hop 2.
    if route_1_facts is None:
        route_1_facts = route_1_hops
    if route_2_facts is None:
        route_2_facts = route_2_hops
    return build_route_memory_graph_payload(
        [
            _report("observation-1", "example.com", "203.0.113.10", "a", hops=route_1_hops, hop_facts=route_1_facts),
            _report("observation-2", "example.org", "203.0.113.20", "b", hops=route_2_hops, hop_facts=route_2_facts),
        ],
        source_node="example-server",
    )


def test_graph_payload_supports_shared_segments_and_divergence():
    payload = build_route_memory_graph_payload(
        [_report("observation-1", "example.com", "203.0.113.10", "a"), _report("observation-2", "example.org", "203.0.113.11", "b")],
        source_node="example-server",
    )
    assert payload["schema"] == "route_memory_graph.v1"
    assert len(payload["routes"]) == 2
    assert payload["segments"]
    assert payload["shared_paths"]
    assert payload["divergences"]
    assert {"routes", "nodes", "edges", "segments", "divergences", "legend"} <= set(payload)


def test_graph_payload_projects_shared_nodes_and_remaps_shared_edges():
    route_1_hops = [
        {"hop_index": 1, "ip": "192.0.2.1", "raw_host": "gw", "hop_type": "local_lan", "confidence": "high", "evidence": {"kind": "synthetic"}},
        {"hop_index": 2, "ip": "198.51.100.1", "raw_host": "core", "hop_type": "public", "confidence": "high", "evidence": {"kind": "synthetic"}},
        {"hop_index": 3, "ip": "203.0.113.10", "raw_host": "dest-a", "hop_type": "destination", "confidence": "high", "evidence": {"kind": "synthetic"}},
    ]
    route_2_hops = [
        {"hop_index": 1, "ip": "192.0.2.1", "raw_host": "gw", "hop_type": "local_lan", "confidence": "high", "evidence": {"kind": "synthetic"}},
        {"hop_index": 2, "ip": "198.51.100.1", "raw_host": "core", "hop_type": "public", "confidence": "high", "evidence": {"kind": "synthetic"}},
        {"hop_index": 3, "ip": "203.0.113.20", "raw_host": "dest-b", "hop_type": "destination", "confidence": "high", "evidence": {"kind": "synthetic"}},
    ]
    payload = _route_pair_payload(route_1_hops, route_2_hops)
    assert any(node["shared"] for node in payload["nodes"])

    shared_nodes = {node["canonical_key"]: node for node in payload["nodes"] if node["shared"]}
    assert shared_nodes["ip:192.0.2.1"]["route_ids"] == ["route_1", "route_2"]
    assert shared_nodes["ip:198.51.100.1"]["route_ids"] == ["route_1", "route_2"]

    shared_edges = [edge for edge in payload["edges"] if edge["shared"]]
    assert {(edge["source_key"], edge["target_key"], edge["edge_type"]) for edge in shared_edges} == {
        ("ip:192.0.2.1", "ip:198.51.100.1", "route_hop")
    }
    shared_edge = next(edge for edge in shared_edges if edge["source_key"] == "ip:192.0.2.1" and edge["target_key"] == "ip:198.51.100.1")
    assert shared_edge["route_ids"] == ["route_1", "route_2"]

    source_ids = {node["canonical_key"]: node["node_id"] for node in payload["nodes"]}
    assert shared_edge["source"] == source_ids["ip:192.0.2.1"]
    assert shared_edge["target"] == source_ids["ip:198.51.100.1"]


def test_graph_payload_keeps_divergent_final_edges_separate():
    route_1_hops = [
        {"hop_index": 1, "ip": "192.0.2.1", "raw_host": "gw", "hop_type": "local_lan", "confidence": "high", "evidence": {"kind": "synthetic"}},
        {"hop_index": 2, "ip": "198.51.100.1", "raw_host": "core", "hop_type": "public", "confidence": "high", "evidence": {"kind": "synthetic"}},
        {"hop_index": 3, "ip": "203.0.113.10", "raw_host": "dest-a", "hop_type": "destination", "confidence": "high", "evidence": {"kind": "synthetic"}},
    ]
    route_2_hops = [
        {"hop_index": 1, "ip": "192.0.2.1", "raw_host": "gw", "hop_type": "local_lan", "confidence": "high", "evidence": {"kind": "synthetic"}},
        {"hop_index": 2, "ip": "198.51.100.1", "raw_host": "core", "hop_type": "public", "confidence": "high", "evidence": {"kind": "synthetic"}},
        {"hop_index": 3, "ip": "203.0.113.20", "raw_host": "dest-b", "hop_type": "destination", "confidence": "high", "evidence": {"kind": "synthetic"}},
    ]
    payload = _route_pair_payload(route_1_hops, route_2_hops)
    final_edges = [edge for edge in payload["edges"] if edge["source_key"] == "ip:198.51.100.1" and edge["edge_type"] == "route_hop"]
    assert {edge["target_key"] for edge in final_edges} == {"ip:203.0.113.10", "ip:203.0.113.20"}
    assert all(edge["shared"] is False for edge in final_edges)
    final_nodes = [node for node in payload["nodes"] if node["ip"] in {"203.0.113.10", "203.0.113.20"}]
    assert len(final_nodes) == 2
    assert all(node["shared"] is False for node in final_nodes)


def test_graph_payload_does_not_share_unknown_only_nodes():
    route_1_hops = [
        {"hop_index": 1, "ip": None, "raw_host": None, "hop_type": "unknown", "confidence": "low", "evidence": {"kind": "synthetic"}},
        {"hop_index": 2, "ip": "203.0.113.10", "raw_host": "dest-a", "hop_type": "destination", "confidence": "high", "evidence": {"kind": "synthetic"}},
    ]
    route_2_hops = [
        {"hop_index": 1, "ip": None, "raw_host": None, "hop_type": "unknown", "confidence": "low", "evidence": {"kind": "synthetic"}},
        {"hop_index": 2, "ip": "203.0.113.20", "raw_host": "dest-b", "hop_type": "destination", "confidence": "high", "evidence": {"kind": "synthetic"}},
    ]
    payload = _route_pair_payload(route_1_hops, route_2_hops, route_1_facts=route_1_hops, route_2_facts=route_2_hops)
    unknown_nodes = [node for node in payload["nodes"] if node["canonical_key"].startswith("unknown:")]
    assert len(unknown_nodes) == 2
    assert all(node["shared"] is False for node in unknown_nodes)
    assert {tuple(node["route_ids"]) for node in unknown_nodes} == {("route_1",), ("route_2",)}


def test_graph_payload_preserves_shared_segments_when_edges_share():
    payload = build_route_memory_graph_payload(
        [_report("observation-1", "example.com", "203.0.113.10", "a"), _report("observation-2", "example.org", "203.0.113.11", "b")],
        source_node="example-server",
    )
    assert any(segment["shared"] for segment in payload["segments"])
    assert all("route_ids" in segment for segment in payload["segments"])


def test_graph_payload_does_not_attribute_private_ip_to_public_asn():
    payload = build_route_memory_graph_payload([_report("observation-1", "example.com", "203.0.113.10", "a")], source_node="example-server")
    hop_nodes = [node for node in payload["nodes"] if node["node_type"] == "hop"]
    assert hop_nodes
    private_nodes = [node for node in hop_nodes if node.get("ip") and node["ip"].startswith("10.")]
    assert private_nodes
    assert private_nodes[0]["asn"] is None


def test_graph_payload_prefers_resolved_hop_fact():
    facts = [
        {"hop_index": 2, "ip": None, "hop_type": "unknown", "evidence": []},
        {"hop_index": 2, "ip": "1.1.1.1", "hop_type": "public", "origin_asn": 64510, "evidence": ["synthetic"]},
    ]
    payload = build_route_memory_graph_payload(
        [_report("observation-1", "example.com", "203.0.113.10", "a", hop_facts=facts)],
        source_node="example-worker",
    )
    hop_nodes = [node for node in payload["nodes"] if node["node_type"] == "hop"]
    assert len(hop_nodes) == 1
    assert hop_nodes[0]["ip"] == "1.1.1.1"
    assert hop_nodes[0]["asn"] == 64510
    assert hop_nodes[0]["label"] == "AS64510"


@pytest.mark.parametrize("address, expected_asn", [
    ("10.0.0.2", None),
    ("172.16.0.2", None),
    ("192.168.0.2", None),
    ("100.64.0.2", None),
    ("127.0.0.1", None),
    ("169.254.0.2", None),
    ("fd00::2", None),
    ("fe80::2", None),
    ("192.0.2.2", None),
    ("198.51.100.2", None),
    ("203.0.113.2", None),
    ("2001:db8::2", None),
    ("invalid-ip", None),
    ("", None),
    ("1.1.1.1", 64510),
    ("2606:4700:4700::1111", 64510),
    (None, 64510),
])
def test_graph_payload_validates_direct_asn_scope_without_mutating_facts(address, expected_asn):
    fact = {"hop_index": 1, "ip": address, "hop_type": "public", "origin_asn": 64510, "evidence": ["synthetic"]}
    report = _report("observation-1", "example.com", "203.0.113.10", "a", hop_facts=[fact])
    report["observed_segments"][0]["context_asn"] = 64520
    original = deepcopy(report)
    payload = build_route_memory_graph_payload([report], source_node="example-worker")
    hop = next(node for node in payload["nodes"] if node["node_type"] == "hop")
    assert hop["asn"] == expected_asn
    assert hop["label"] == ("AS64510" if expected_asn is not None else address or "hop")
    assert report == original
    assert "synthetic" in hop["evidence"]
    segment = next(node for node in payload["nodes"] if node["node_type"] == "segment")
    assert segment["asn"] == 64520


def test_graph_payload_shared_private_fact_keeps_null_asn():
    fact = {"hop_index": 1, "ip": "10.0.0.2", "hop_type": "public", "origin_asn": 64510, "evidence": ["synthetic"]}
    reports = [
        _report("observation-1", "example.com", "203.0.113.10", "a", hop_facts=[dict(fact)]),
        _report("observation-2", "example.org", "203.0.113.20", "b", hop_facts=[dict(fact)]),
    ]
    payload = build_route_memory_graph_payload(reports, source_node="example-worker")
    hops = [node for node in payload["nodes"] if node["node_type"] == "hop"]
    assert len(hops) == 1
    assert hops[0]["canonical_key"] == "ip:10.0.0.2"
    assert hops[0]["shared"] is True
    assert hops[0]["route_ids"] == ["route_1", "route_2"]
    assert hops[0]["asn"] is None
