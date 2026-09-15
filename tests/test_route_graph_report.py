from __future__ import annotations

from app.services.route_graph_builder import build_route_graph_report


def test_route_graph_report_summary_and_hops():
    route_graph = {
        "schema_version": "routegraph.v1",
        "graph_uid": "rg-test",
        "source": {"run_uid": "run-1", "target": "8.8.8.8", "ip_family": "ipv4", "generated_at": "2026-06-17T00:00:00Z"},
        "summary": {
            "logical_hop_count": 2,
            "responding_hop_count": 1,
            "silent_hop_count": 1,
            "private_hop_count": 1,
            "public_hop_count": 1,
            "destination_reached": True,
            "confidence": "partial",
        },
        "nodes": [
            {
                "id": "hop-1",
                "kind": "private_hop",
                "hop_index": 1,
                "ip": "10.0.0.1",
                "latency_ms": 1.2,
                "is_private": True,
                "is_silent": False,
                "is_destination": False,
                "asn": None,
                "as_name": None,
                "confidence": "low",
                "evidence": [],
                "badges": [],
            },
            {
                "id": "hop-2",
                "kind": "destination",
                "hop_index": 2,
                "ip": "8.8.8.8",
                "latency_ms": 2.3,
                "is_private": False,
                "is_silent": False,
                "is_destination": True,
                "asn": 15169,
                "as_name": "Google",
                "confidence": "high",
                "evidence": [{"source": "external_hop_context"}],
                "badges": ["destination"],
            },
        ],
        "edges": [{"id": "edge-hop-1-hop-2", "source": "hop-1", "target": "hop-2", "kind": "logical_next_hop", "confidence": "partial"}],
        "warnings": ["hop 2 sem resposta explícita."],
        "adapter_hints": {"preferred_layout": "left_to_right", "supports_timeline_comparison": False},
    }
    report = build_route_graph_report(route_graph)
    assert report["schema_version"] == "routegraph.v1"
    assert report["graph_uid"] == "rg-test"
    assert report["total_nodes"] == 2
    assert report["total_edges"] == 1
    assert report["asn_count"] == 1
    assert report["missing_asn_count"] == 1
    assert report["as_name_count"] == 1
    assert report["missing_as_name_count"] == 1
    assert report["latency_count"] == 2
    assert report["missing_latency_count"] == 0
    assert report["evidence_count"] == 1
    assert report["missing_evidence_count"] == 1
    assert report["warnings_total"] == 1
    assert report["hops"][0]["evidence_count"] == 0
    assert report["hops"][1]["evidence_count"] == 1

