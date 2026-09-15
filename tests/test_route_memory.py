from __future__ import annotations

from app.services import route_memory as rm


def _synthetic_on_net_hops(destination_ip: str, destination_asn: int) -> list[dict[str, object]]:
    return [
        {"hop_number": 1, "hop_ip": "10.20.0.1", "responded": True, "rtt_avg_ms": 1.0, "raw_line": "1"},
        {"hop_number": 2, "hop_ip": None, "responded": False, "rtt_avg_ms": None, "raw_line": "2"},
        {"hop_number": 3, "hop_ip": "10.22.0.14", "responded": True, "rtt_avg_ms": 5.0, "raw_line": "3"},
        {"hop_number": 4, "hop_ip": "10.22.0.18", "responded": True, "rtt_avg_ms": 6.0, "raw_line": "4"},
        {"hop_number": 5, "hop_ip": "10.22.0.19", "responded": True, "rtt_avg_ms": 7.0, "raw_line": "5"},
        {"hop_number": 6, "hop_ip": "10.22.0.17", "responded": True, "rtt_avg_ms": 8.0, "raw_line": "6"},
        {"hop_number": 7, "hop_ip": "10.22.0.12", "responded": True, "rtt_avg_ms": 9.0, "raw_line": "7"},
        {"hop_number": 8, "hop_ip": destination_ip, "responded": True, "rtt_avg_ms": 10.0, "raw_line": "8"},
    ]


def _patch_synthetic_observation(monkeypatch, destination_ip: str, target_label: str) -> None:
    # No related graph runs exist in this synthetic observation fixture.
    monkeypatch.setattr(rm, "_fetch_related_routegraph_runs", lambda resolved_ip, measurement_id: [])
    monkeypatch.setattr(
        rm,
        "lookup_bgp_by_ip",
        lambda ip: {
            "matched_prefix": f"{destination_ip}/32",
            "origin_asn": 64510 if destination_ip.endswith("17") else 64520 if destination_ip.endswith("19") else 64510,
            "sample_as_paths": ["65000 64510"],
        }
        if ip == destination_ip
        else None,
    )
    monkeypatch.setattr(
        rm,
        "_fetch_latest_observation",
        lambda target, resolved_ip, measurement_id=None: {
            "id": 42,
            "target": destination_ip,
            "target_label": target_label,
            "source_label": "example-server",
            "mode": "mtr",
            "status": "SUCCESS",
            "measured_at": "2026-06-23T10:00:00Z",
            "command": "mtr",
        },
    )


def test_on_net_destination_edge_short_route(monkeypatch):
    destination_ip = "93.184.216.17"
    _patch_synthetic_observation(monkeypatch, destination_ip, "synthetic-on-net")
    monkeypatch.setattr(rm, "_fetch_observation_hops", lambda measurement_id: _synthetic_on_net_hops(destination_ip, 64510))
    monkeypatch.setattr(rm, "_fetch_related_routegraph_runs", lambda resolved_ip, measurement_id: [])

    report = rm.build_route_memory_report("synthetic-on-net", resolved_ip=destination_ip)

    assert [segment["segment_type"] for segment in report["observed_segments"]] == [
        "local_lan",
        "silent_gap",
        "operator_private_core",
        "on_net_destination_edge",
    ]
    assert report["observed_segments"][2]["hop_count"] == 5
    assert report["observed_segments"][3]["hop_count"] == 1
    assert "public_backbone" not in [segment["segment_type"] for segment in report["observed_segments"]]
    assert report["segment_matches"][-1]["match_type"] == "destination_asn_match"
    assert report["segment_matches"][2]["divergence_type"] == "private_branch_variation"
    assert report["what_routebrain_does_not_know"][-1].startswith("A segmentação ainda é heurística")


def test_private_branch_variation_between_similar_on_net_routes(monkeypatch):
    destination_a = "93.184.216.17"
    destination_b = "93.184.216.18"
    _patch_synthetic_observation(monkeypatch, destination_a, "synthetic-on-net-a")
    monkeypatch.setattr(rm, "_fetch_observation_hops", lambda measurement_id: _synthetic_on_net_hops(destination_a, 64510))
    report_a = rm.build_route_memory_report("synthetic-on-net-a", resolved_ip=destination_a)

    _patch_synthetic_observation(monkeypatch, destination_b, "synthetic-on-net-b")
    monkeypatch.setattr(
        rm,
        "_fetch_observation_hops",
        lambda measurement_id: [
            {"hop_number": 1, "hop_ip": "10.20.0.1", "responded": True, "rtt_avg_ms": 1.0, "raw_line": "1"},
            {"hop_number": 2, "hop_ip": None, "responded": False, "rtt_avg_ms": None, "raw_line": "2"},
            {"hop_number": 3, "hop_ip": "10.22.0.14", "responded": True, "rtt_avg_ms": 5.0, "raw_line": "3"},
            {"hop_number": 4, "hop_ip": "10.22.0.18", "responded": True, "rtt_avg_ms": 6.0, "raw_line": "4"},
            {"hop_number": 5, "hop_ip": "10.22.0.19", "responded": True, "rtt_avg_ms": 7.0, "raw_line": "5"},
            {"hop_number": 6, "hop_ip": "10.22.0.17", "responded": True, "rtt_avg_ms": 8.0, "raw_line": "6"},
            {"hop_number": 7, "hop_ip": "10.22.0.13", "responded": True, "rtt_avg_ms": 9.0, "raw_line": "7"},
            {"hop_number": 8, "hop_ip": destination_b, "responded": True, "rtt_avg_ms": 10.0, "raw_line": "8"},
        ],
    )
    report_b = rm.build_route_memory_report("synthetic-on-net-b", resolved_ip=destination_b)

    comparison = rm.compare_route_memory_reports(report_a, report_b)
    assert comparison["private_branch_variation"] is True
    assert comparison["operational_divergence"] is False
    assert comparison["destination_asn_match"] is True
    assert report_a["route_known_fraction"] >= 0.75
    assert report_b["route_known_fraction"] >= 0.75
    assert report_a["segment_matches"][-1]["match_type"] == "destination_asn_match"
    assert report_b["segment_matches"][-1]["match_type"] == "destination_asn_match"


def test_operational_divergence_with_destination_asn_change(monkeypatch):
    destination_a = "93.184.216.17"
    destination_c = "93.184.216.19"
    _patch_synthetic_observation(monkeypatch, destination_a, "synthetic-on-net-a")
    monkeypatch.setattr(rm, "_fetch_observation_hops", lambda measurement_id: _synthetic_on_net_hops(destination_a, 64510))
    report_a = rm.build_route_memory_report("synthetic-on-net-a", resolved_ip=destination_a)

    monkeypatch.setattr(
        rm,
        "lookup_bgp_by_ip",
        lambda ip: {
            "matched_prefix": f"{destination_c}/32",
            "origin_asn": 64520,
            "sample_as_paths": ["65000 64520"],
        }
        if ip == destination_c
        else None,
    )
    monkeypatch.setattr(
        rm,
        "_fetch_latest_observation",
        lambda target, resolved_ip, measurement_id=None: {
            "id": 43,
            "target": destination_c,
            "target_label": "synthetic-on-net-c",
            "source_label": "example-server",
            "mode": "mtr",
            "status": "SUCCESS",
            "measured_at": "2026-06-23T10:00:00Z",
            "command": "mtr",
        },
    )
    monkeypatch.setattr(
        rm,
        "_fetch_observation_hops",
        lambda measurement_id: [
            {"hop_number": 1, "hop_ip": "10.20.0.1", "responded": True, "rtt_avg_ms": 1.0, "raw_line": "1"},
            {"hop_number": 2, "hop_ip": None, "responded": False, "rtt_avg_ms": None, "raw_line": "2"},
            {"hop_number": 3, "hop_ip": "10.22.0.14", "responded": True, "rtt_avg_ms": 5.0, "raw_line": "3"},
            {"hop_number": 4, "hop_ip": "10.22.0.18", "responded": True, "rtt_avg_ms": 6.0, "raw_line": "4"},
            {"hop_number": 5, "hop_ip": "10.22.0.19", "responded": True, "rtt_avg_ms": 7.0, "raw_line": "5"},
            {"hop_number": 6, "hop_ip": "10.22.0.17", "responded": True, "rtt_avg_ms": 8.0, "raw_line": "6"},
            {"hop_number": 7, "hop_ip": "10.22.0.12", "responded": True, "rtt_avg_ms": 9.0, "raw_line": "7"},
            {"hop_number": 8, "hop_ip": destination_c, "responded": True, "rtt_avg_ms": 10.0, "raw_line": "8"},
        ],
    )
    report_c = rm.build_route_memory_report("synthetic-on-net-c", resolved_ip=destination_c)

    comparison = rm.compare_route_memory_reports(report_a, report_c)
    assert comparison["operational_divergence"] is True
    assert comparison["destination_asn_match"] is False
    assert report_c["segment_matches"][-1]["match_type"] == "destination_asn_match"
    assert report_a["segment_matches"][2]["divergence_type"] == "private_branch_variation"
    assert comparison["segment_comparisons"][-1]["divergence_type"] == "operational_divergence"
    assert report_c["segment_matches"][-1]["divergence_type"] == "structural_divergence"


def test_private_hops_do_not_receive_public_asn_directly(monkeypatch):
    destination_ip = "93.184.216.17"
    _patch_synthetic_observation(monkeypatch, destination_ip, "synthetic-protection")
    monkeypatch.setattr(rm, "_fetch_observation_hops", lambda measurement_id: _synthetic_on_net_hops(destination_ip, 64510))
    report = rm.build_route_memory_report("synthetic-protection", resolved_ip=destination_ip)

    private_segments = [segment for segment in report["observed_segments"] if segment["segment_type"] == "operator_private_core"]
    assert private_segments
    assert private_segments[0]["context_asn"] is None
    assert private_segments[0]["first_public_asn"] is None
    assert private_segments[0]["last_public_asn"] is None
    assert any("Private hops do not receive public ASN attribution directly" in item for item in report["what_routebrain_does_not_know"])
