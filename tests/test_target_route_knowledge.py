from __future__ import annotations

from app.services import target_route_knowledge as trk


def test_known_bgp_and_missing_traceroute(monkeypatch):
    monkeypatch.setattr(
        trk,
        "lookup_bgp_by_ip",
        lambda ip: {
            "matched_prefix": "159.148.147.0/24",
            "origin_asn": 51894,
            "sample_as_paths": ["49788 1299 5518 51894"],
        },
    )
    monkeypatch.setattr(trk, "_fetch_existing_measurements", lambda resolved_ip: ([], []))
    report = trk.build_target_route_knowledge_report("wiki.mikrotik.com", resolved_ip="159.148.147.244")
    assert report["destination_bgp_prefix"] == "159.148.147.0/24"
    assert report["destination_origin_asn"] == 51894
    assert report["knowledge_status"] == "bgp_known_traceroute_missing"
    assert report["has_existing_traceroute_measurement"] is False


def test_unknown_bgp_context(monkeypatch):
    monkeypatch.setattr(trk, "lookup_bgp_by_ip", lambda ip: None)
    monkeypatch.setattr(trk, "_fetch_existing_measurements", lambda resolved_ip: ([], []))
    report = trk.build_target_route_knowledge_report("example.test", resolved_ip="8.8.4.4")
    assert report["knowledge_status"] == "unknown_bgp_context"
    assert report["destination_bgp_prefix"] is None


def test_private_destination_no_public_bgp():
    report = trk.build_target_route_knowledge_report("private.example", resolved_ip="10.0.0.10")
    assert report["knowledge_status"] == "private_destination_no_public_bgp"
    assert report["destination_bgp_prefix"] is None
